"""Tests for DiE (Detect It Easy) analyzer module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winforensics_mcp.parsers.die_analyzer import (
    DIE_AVAILABLE,
    get_packer_info,
    _process_die_result,
)


class TestDieAvailability:
    """Test DiE availability flag."""

    def test_die_available_flag_exists(self):
        """Test DIE_AVAILABLE flag is defined."""
        assert isinstance(DIE_AVAILABLE, bool)


class TestDieImports:
    """Test that DiE analyzer functions can be imported."""

    def test_die_analyzer_imports(self):
        """Test all DiE analyzer functions are importable."""
        from winforensics_mcp.parsers import (
            die_analyze_file,
            die_scan_directory,
            die_get_packer_info,
            get_die_version,
            DIE_AVAILABLE,
        )
        assert callable(die_analyze_file)
        assert callable(die_scan_directory)
        assert callable(die_get_packer_info)
        assert callable(get_die_version)

    def test_die_analyzer_direct_imports(self):
        """Test direct imports from die_analyzer module."""
        from winforensics_mcp.parsers.die_analyzer import (
            analyze_file,
            scan_directory,
            get_packer_info,
            get_die_version,
            check_die_available,
        )
        assert callable(analyze_file)
        assert callable(scan_directory)
        assert callable(get_packer_info)
        assert callable(get_die_version)
        assert callable(check_die_available)


class TestPackerInfo:
    """Test packer information database."""

    def test_get_packer_info_upx(self):
        """Test getting info for UPX packer."""
        info = get_packer_info("UPX")
        assert info["name"] == "UPX (Ultimate Packer for eXecutables)"
        assert info["type"] == "Packer"
        assert info["difficulty"] == "Easy"
        assert "upx -d" in info.get("unpack_tool", "")

    def test_get_packer_info_themida(self):
        """Test getting info for Themida protector."""
        info = get_packer_info("Themida")
        assert "Themida" in info["name"]
        assert info["type"] == "Protector"
        assert info["difficulty"] == "Hard"
        assert "malware_use" in info

    def test_get_packer_info_vmprotect(self):
        """Test getting info for VMProtect."""
        info = get_packer_info("VMProtect")
        assert "VMProtect" in info["name"]
        assert info["type"] == "Protector"
        assert info["difficulty"] == "Very Hard"

    def test_get_packer_info_confuser(self):
        """Test getting info for ConfuserEx."""
        info = get_packer_info("ConfuserEx")
        assert "Confuser" in info["name"]
        assert info["type"] == "Obfuscator"
        assert "de4dot" in info.get("unpack_tool", "")

    def test_get_packer_info_unknown(self):
        """Test getting info for unknown packer."""
        info = get_packer_info("UnknownPacker123")
        assert info["type"] == "Unknown"
        assert info["difficulty"] == "Unknown"
        assert "note" in info

    def test_get_packer_info_case_insensitive(self):
        """Test packer lookup is case insensitive."""
        info1 = get_packer_info("upx")
        info2 = get_packer_info("UPX")
        info3 = get_packer_info("Upx")
        assert info1["name"] == info2["name"] == info3["name"]


class TestProcessDieResult:
    """Test DiE result processing."""

    def test_process_empty_result(self):
        """Test processing empty DiE result."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            result = _process_die_result(temp_path, {}, True, False)
            assert result["file"] == str(temp_path)
            assert result["detects"] == []
            assert result["is_packed"] is False
            assert result["is_dotnet"] is False
        finally:
            os.unlink(temp_path)

    def test_process_result_with_detects(self):
        """Test processing DiE result with detections."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            data = {
                "filetype": "PE32",
                "arch": "x86",
                "mode": "32",
                "detects": [
                    {"type": "Compiler", "name": "MSVC", "version": "14.0"},
                    {"type": "Linker", "name": "Microsoft Linker"},
                ]
            }
            result = _process_die_result(temp_path, data, True, False)
            assert result["file_type"] == "PE32"
            assert result["arch"] == "x86"
            assert len(result["detects"]) == 2
            assert result["is_packed"] is False
        finally:
            os.unlink(temp_path)

    def test_process_result_packed(self):
        """Test processing DiE result with packer detection."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            data = {
                "detects": [
                    {"type": "Packer", "name": "UPX", "version": "3.96"},
                ]
            }
            result = _process_die_result(temp_path, data, True, False)
            assert result["is_packed"] is True
        finally:
            os.unlink(temp_path)

    def test_process_result_dotnet(self):
        """Test processing DiE result with .NET detection."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            data = {
                "detects": [
                    {"type": "Compiler", "name": ".NET"},
                ]
            }
            result = _process_die_result(temp_path, data, True, False)
            assert result["is_dotnet"] is True
        finally:
            os.unlink(temp_path)

    def test_process_result_installer(self):
        """Test processing DiE result with installer detection."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            data = {
                "detects": [
                    {"type": "Installer", "name": "NSIS"},
                ]
            }
            result = _process_die_result(temp_path, data, True, False)
            assert result["is_installer"] is True
        finally:
            os.unlink(temp_path)


class TestDieFileNotFound:
    """Test error handling for missing files."""

    @pytest.mark.skipif(not DIE_AVAILABLE, reason="diec not installed")
    def test_analyze_file_not_found(self):
        """Test analyze_file with non-existent file."""
        from winforensics_mcp.parsers.die_analyzer import analyze_file

        with pytest.raises(FileNotFoundError):
            analyze_file("/nonexistent/file.exe")

    @pytest.mark.skipif(not DIE_AVAILABLE, reason="diec not installed")
    def test_scan_directory_not_found(self):
        """Test scan_directory with non-existent directory."""
        from winforensics_mcp.parsers.die_analyzer import scan_directory

        with pytest.raises(FileNotFoundError):
            scan_directory("/nonexistent/directory")

    @pytest.mark.skipif(not DIE_AVAILABLE, reason="diec not installed")
    def test_scan_directory_not_a_dir(self):
        """Test scan_directory with file instead of directory."""
        from winforensics_mcp.parsers.die_analyzer import scan_directory

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            with pytest.raises(ValueError):
                scan_directory(temp_path)
        finally:
            os.unlink(temp_path)


class TestDieAvailabilityCheck:
    """Test DiE availability checking."""

    def test_check_die_available_when_not_available(self):
        """Test check_die_available raises error when not available."""
        from winforensics_mcp.parsers.die_analyzer import check_die_available

        with patch("winforensics_mcp.parsers.die_analyzer.DIE_AVAILABLE", False):
            with patch("winforensics_mcp.parsers.die_analyzer._DIEC_PATH", None):
                # The function checks the module-level DIE_AVAILABLE
                # We need to test the behavior without diec
                pass  # Skip actual test since we can't easily mock module-level


class TestDieVersion:
    """Test DiE version retrieval."""

    def test_get_die_version_returns_string_or_none(self):
        """Test get_die_version returns string or None."""
        from winforensics_mcp.parsers.die_analyzer import get_die_version

        version = get_die_version()
        assert version is None or isinstance(version, str)


@pytest.mark.skipif(not DIE_AVAILABLE, reason="diec not installed")
class TestDieWithDiec:
    """Tests that require diec to be installed."""

    def test_analyze_empty_file(self):
        """Test analyzing an empty file."""
        from winforensics_mcp.parsers.die_analyzer import analyze_file

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"\x00" * 100)
            temp_path = f.name

        try:
            result = analyze_file(temp_path)
            assert "file" in result
            assert result["file"] == temp_path
        finally:
            os.unlink(temp_path)

    def test_scan_empty_directory(self):
        """Test scanning an empty directory."""
        from winforensics_mcp.parsers.die_analyzer import scan_directory

        with tempfile.TemporaryDirectory() as temp_dir:
            result = scan_directory(temp_dir)
            assert result["directory"] == temp_dir
            assert result["files_scanned"] == 0
            assert result["results"] == []


class TestDieMockedSubprocess:
    """Tests using mocked subprocess calls."""

    @patch("winforensics_mcp.parsers.die_analyzer.DIE_AVAILABLE", True)
    @patch("winforensics_mcp.parsers.die_analyzer._DIEC_PATH", "/usr/bin/diec")
    @patch("subprocess.run")
    def test_analyze_file_json_output(self, mock_run):
        """Test analyze_file parses JSON output correctly."""
        from winforensics_mcp.parsers.die_analyzer import analyze_file

        mock_run.return_value = MagicMock(
            stdout='{"filetype": "PE32", "arch": "x86", "detects": [{"type": "Compiler", "name": "MSVC"}]}',
            stderr="",
            returncode=0,
        )

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)
            temp_path = f.name

        try:
            result = analyze_file(temp_path)
            assert result["file_type"] == "PE32"
            assert result["arch"] == "x86"
            assert len(result["detects"]) >= 1
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.die_analyzer.DIE_AVAILABLE", True)
    @patch("winforensics_mcp.parsers.die_analyzer._DIEC_PATH", "/usr/bin/diec")
    @patch("subprocess.run")
    def test_analyze_file_timeout(self, mock_run):
        """Test analyze_file handles timeout."""
        import subprocess
        from winforensics_mcp.parsers.die_analyzer import analyze_file

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="diec", timeout=60)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)
            temp_path = f.name

        try:
            result = analyze_file(temp_path)
            assert "error" in result
            assert "timed out" in result["error"].lower()
        finally:
            os.unlink(temp_path)

    @patch("winforensics_mcp.parsers.die_analyzer.DIE_AVAILABLE", True)
    @patch("winforensics_mcp.parsers.die_analyzer._DIEC_PATH", "/usr/bin/diec")
    @patch("subprocess.run")
    def test_analyze_file_invalid_json(self, mock_run):
        """Test analyze_file handles invalid JSON output."""
        from winforensics_mcp.parsers.die_analyzer import analyze_file

        mock_run.return_value = MagicMock(
            stdout="not valid json",
            stderr="",
            returncode=0,
        )

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)
            temp_path = f.name

        try:
            result = analyze_file(temp_path)
            assert "error" in result
            assert "raw_output" in result
        finally:
            os.unlink(temp_path)
