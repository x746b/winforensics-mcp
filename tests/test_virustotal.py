"""Tests for VirusTotal client module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winforensics_mcp.parsers.virustotal_client import (
    VT_AVAILABLE,
    _normalize_hash,
    clear_cache,
    get_api_key,
    get_cache_stats,
)


class TestHashNormalization:
    """Test hash normalization and type detection."""

    def test_md5_hash(self):
        """Test MD5 hash detection (32 chars)."""
        hash_val, hash_type = _normalize_hash("D41D8CD98F00B204E9800998ECF8427E")
        assert hash_type == "md5"
        assert hash_val == "d41d8cd98f00b204e9800998ecf8427e"  # Lowercase

    def test_sha1_hash(self):
        """Test SHA1 hash detection (40 chars)."""
        hash_val, hash_type = _normalize_hash("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
        assert hash_type == "sha1"
        assert hash_val == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_sha256_hash(self):
        """Test SHA256 hash detection (64 chars)."""
        hash_val, hash_type = _normalize_hash(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        )
        assert hash_type == "sha256"
        assert len(hash_val) == 64

    def test_invalid_hash_length(self):
        """Test invalid hash length detection."""
        hash_val, hash_type = _normalize_hash("abc123")
        assert hash_type == "unknown"

    def test_hash_with_whitespace(self):
        """Test hash normalization strips whitespace."""
        hash_val, hash_type = _normalize_hash("  D41D8CD98F00B204E9800998ECF8427E  ")
        assert hash_type == "md5"
        assert hash_val == "d41d8cd98f00b204e9800998ecf8427e"


class TestApiKeyRetrieval:
    """Test API key retrieval methods."""

    def test_api_key_from_env(self):
        """Test API key from environment variable."""
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key-123"}):
            key = get_api_key()
            assert key == "test-key-123"

    def test_api_key_from_env_with_whitespace(self):
        """Test API key from env strips whitespace."""
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "  test-key-456  "}):
            key = get_api_key()
            assert key == "test-key-456"

    def test_api_key_from_config_file(self):
        """Test API key from config file."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove env var if present
            os.environ.pop("VIRUSTOTAL_API_KEY", None)

            with tempfile.TemporaryDirectory() as tmpdir:
                config_dir = Path(tmpdir) / ".config" / "winforensics-mcp"
                config_dir.mkdir(parents=True)
                config_file = config_dir / "vt_api_key"
                config_file.write_text("file-key-789\n")

                with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                    key = get_api_key()
                    assert key == "file-key-789"

    def test_api_key_none_when_not_configured(self):
        """Test API key returns None when not configured."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("VIRUSTOTAL_API_KEY", None)

            with tempfile.TemporaryDirectory() as tmpdir:
                with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                    key = get_api_key()
                    assert key is None


class TestCacheManagement:
    """Test cache operations."""

    def test_clear_cache_empty(self):
        """Test clearing empty cache returns 0."""
        clear_cache()  # Ensure empty
        count = clear_cache()
        assert count == 0

    def test_cache_stats_empty(self):
        """Test cache stats on empty cache."""
        clear_cache()
        stats = get_cache_stats()
        assert stats["total_entries"] == 0
        assert stats["valid_entries"] == 0
        assert stats["expired_entries"] == 0
        assert stats["ttl_hours"] == 24


class TestVtAvailability:
    """Test VT availability flag."""

    def test_vt_available_flag_exists(self):
        """Test VT_AVAILABLE flag is defined."""
        assert isinstance(VT_AVAILABLE, bool)


@pytest.mark.skipif(not VT_AVAILABLE, reason="vt-py not installed")
class TestVtClientWithLibrary:
    """Tests that require vt-py to be installed."""

    @patch("winforensics_mcp.parsers.virustotal_client.check_api_key")
    def test_lookup_hash_invalid_length(self, mock_check_key):
        """Test lookup_hash with invalid hash length returns error."""
        from winforensics_mcp.parsers.virustotal_client import lookup_hash

        mock_check_key.return_value = "test-key"
        result = lookup_hash("invalid")
        assert result["found"] is False
        assert result["hash_type"] == "unknown"
        assert "error" in result

    @patch("winforensics_mcp.parsers.virustotal_client.check_api_key")
    @patch("winforensics_mcp.parsers.virustotal_client._rate_limit")
    @patch("vt.Client")
    def test_lookup_hash_not_found(self, mock_client_class, mock_rate_limit, mock_check_key):
        """Test lookup_hash when hash not found in VT."""
        import vt

        from winforensics_mcp.parsers.virustotal_client import clear_cache, lookup_hash

        clear_cache()
        mock_check_key.return_value = "test-key"

        # Simulate NotFoundError
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get_object.side_effect = vt.error.APIError("NotFoundError", "NotFoundError: Resource not found")
        mock_client_class.return_value = mock_client

        result = lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result["found"] is False
        assert result["verdict"] == "unknown"

    @patch("winforensics_mcp.parsers.virustotal_client.check_api_key")
    @patch("winforensics_mcp.parsers.virustotal_client._rate_limit")
    @patch("vt.Client")
    def test_lookup_hash_found_malicious(self, mock_client_class, mock_rate_limit, mock_check_key):
        """Test lookup_hash when file is found and malicious."""
        from winforensics_mcp.parsers.virustotal_client import clear_cache, lookup_hash

        clear_cache()
        mock_check_key.return_value = "test-key"

        # Create mock file object with malicious stats
        mock_file = MagicMock()
        mock_file.last_analysis_stats = {
            "malicious": 45,
            "suspicious": 2,
            "harmless": 10,
            "undetected": 15,
        }
        mock_file.last_analysis_results = {
            "Kaspersky": {"category": "malicious", "result": "Trojan.GenericKD"},
            "ESET": {"category": "malicious", "result": "Win32/Trojan"},
        }
        mock_file.sha256 = "abc123"
        mock_file.sha1 = "def456"
        mock_file.md5 = "d41d8cd98f00b204e9800998ecf8427e"
        mock_file.type_description = "Win32 EXE"
        mock_file.size = 12345
        mock_file.names = ["malware.exe"]
        mock_file.tags = ["peexe"]

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get_object.return_value = mock_file
        mock_client_class.return_value = mock_client

        result = lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result["found"] is True
        assert result["verdict"] == "malicious"
        assert result["malicious"] == 45
        assert result["detection_ratio"] == "45/72"

    @patch("winforensics_mcp.parsers.virustotal_client.check_api_key")
    @patch("winforensics_mcp.parsers.virustotal_client._rate_limit")
    @patch("vt.Client")
    def test_lookup_ip_clean(self, mock_client_class, mock_rate_limit, mock_check_key):
        """Test lookup_ip with clean IP."""
        from winforensics_mcp.parsers.virustotal_client import clear_cache, lookup_ip

        clear_cache()
        mock_check_key.return_value = "test-key"

        mock_ip = MagicMock()
        mock_ip.last_analysis_stats = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 50,
            "undetected": 20,
        }
        mock_ip.as_owner = "Google LLC"
        mock_ip.asn = 15169
        mock_ip.country = "US"
        mock_ip.continent = "NA"
        mock_ip.reputation = 0
        mock_ip.tags = []
        mock_ip.network = "8.8.8.0/24"

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get_object.return_value = mock_ip
        mock_client_class.return_value = mock_client

        result = lookup_ip("8.8.8.8")
        assert result["found"] is True
        assert result["verdict"] == "clean"
        assert result["as_owner"] == "Google LLC"
        assert result["country"] == "US"

    @patch("winforensics_mcp.parsers.virustotal_client.check_api_key")
    @patch("winforensics_mcp.parsers.virustotal_client._rate_limit")
    @patch("vt.Client")
    def test_lookup_domain_suspicious(self, mock_client_class, mock_rate_limit, mock_check_key):
        """Test lookup_domain with suspicious domain."""
        from winforensics_mcp.parsers.virustotal_client import clear_cache, lookup_domain

        clear_cache()
        mock_check_key.return_value = "test-key"

        mock_domain = MagicMock()
        mock_domain.last_analysis_stats = {
            "malicious": 1,
            "suspicious": 3,
            "harmless": 40,
            "undetected": 10,
        }
        mock_domain.registrar = "NameCheap"
        mock_domain.reputation = -5
        mock_domain.categories = {"Forcepoint": "suspicious"}
        mock_domain.tags = ["phishing"]
        mock_domain.whois = "Domain: evil.com\nRegistrar: NameCheap"

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get_object.return_value = mock_domain
        mock_client_class.return_value = mock_client

        result = lookup_domain("evil.com")
        assert result["found"] is True
        assert result["verdict"] == "suspicious"
        assert result["registrar"] == "NameCheap"


class TestCaching:
    """Test caching behavior."""

    @pytest.mark.skipif(not VT_AVAILABLE, reason="vt-py not installed")
    @patch("winforensics_mcp.parsers.virustotal_client.check_api_key")
    @patch("winforensics_mcp.parsers.virustotal_client._rate_limit")
    @patch("vt.Client")
    def test_cache_hit(self, mock_client_class, mock_rate_limit, mock_check_key):
        """Test that cached results are returned."""
        from winforensics_mcp.parsers.virustotal_client import clear_cache, lookup_hash

        clear_cache()
        mock_check_key.return_value = "test-key"

        # Setup mock
        mock_file = MagicMock()
        mock_file.last_analysis_stats = {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 20}
        mock_file.sha256 = "abc"
        mock_file.sha1 = "def"
        mock_file.md5 = "d41d8cd98f00b204e9800998ecf8427e"
        mock_file.names = []
        mock_file.tags = []

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get_object.return_value = mock_file
        mock_client_class.return_value = mock_client

        # First call - should hit API
        result1 = lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result1["found"] is True
        assert "_cached" not in result1 or result1.get("_cached") is False

        # Second call - should hit cache
        result2 = lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result2["found"] is True
        assert result2.get("_cached") is True

        # Verify API was only called once
        assert mock_client.get_object.call_count == 1

        # Check cache stats
        stats = get_cache_stats()
        assert stats["total_entries"] >= 1
        assert stats["valid_entries"] >= 1


class TestLookupFile:
    """Test file lookup functionality."""

    @pytest.mark.skipif(not VT_AVAILABLE, reason="vt-py not installed")
    def test_lookup_file_not_found(self):
        """Test lookup_file with non-existent file."""
        from winforensics_mcp.parsers.virustotal_client import lookup_file

        with pytest.raises(FileNotFoundError):
            lookup_file("/nonexistent/file.exe")

    @pytest.mark.skipif(not VT_AVAILABLE, reason="vt-py not installed")
    @patch("winforensics_mcp.parsers.virustotal_client.lookup_hash")
    def test_lookup_file_calculates_hashes(self, mock_lookup_hash):
        """Test lookup_file calculates local hashes."""
        from winforensics_mcp.parsers.virustotal_client import lookup_file

        mock_lookup_hash.return_value = {"found": False, "verdict": "unknown"}

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            f.flush()
            temp_path = f.name

        try:
            result = lookup_file(temp_path)
            assert "local_hashes" in result
            assert "md5" in result["local_hashes"]
            assert "sha1" in result["local_hashes"]
            assert "sha256" in result["local_hashes"]
            assert result["file_path"] == temp_path
            assert "file_size_local" in result
        finally:
            os.unlink(temp_path)
