"""
YARA scanner tests for winforensics-mcp.

Tests verify YARA module imports, rule management, and scanning functionality.
"""
import pytest
from pathlib import Path
import tempfile


class TestYaraImports:
    """Test YARA module imports."""

    def test_yara_scanner_imports(self):
        from winforensics_mcp.parsers import (
            yara_scan_file,
            yara_scan_directory,
            yara_list_rules,
            yara_compile_rules,
            yara_get_default_rules_path,
            YARA_AVAILABLE,
        )
        assert isinstance(YARA_AVAILABLE, bool)

    def test_yara_scanner_direct_imports(self):
        from winforensics_mcp.parsers.yara_scanner import (
            scan_file,
            scan_directory,
            scan_bytes,
            compile_rules,
            list_rules,
            get_default_rules_path,
            YARA_AVAILABLE,
            EXTERNAL_VAR_FILES,
        )
        assert isinstance(YARA_AVAILABLE, bool)
        assert isinstance(EXTERNAL_VAR_FILES, set)


class TestYaraRules:
    """Test YARA rule management."""

    def test_default_rules_path_exists(self):
        from winforensics_mcp.parsers.yara_scanner import get_default_rules_path

        rules_path = get_default_rules_path()
        assert rules_path is not None
        assert rules_path.exists()
        assert rules_path.is_dir()

    def test_bundled_rules_present(self):
        from winforensics_mcp.parsers.yara_scanner import get_default_rules_path

        rules_path = get_default_rules_path()
        yar_files = list(rules_path.glob("*.yar"))

        # Should have multiple rule files
        assert len(yar_files) >= 5

        # Check for key rule files
        rule_names = [f.name for f in yar_files]
        assert "gen_mimikatz.yar" in rule_names
        assert "gen_webshells.yar" in rule_names

    def test_list_rules(self):
        from winforensics_mcp.parsers.yara_scanner import list_rules, YARA_AVAILABLE

        result = list_rules()

        assert "rule_files" in result
        assert "total_files" in result
        assert "usable_files" in result
        assert "source" in result

        assert result["source"] == "bundled"
        assert result["usable_files"] > 0
        assert result["total_files"] >= result["usable_files"]


@pytest.mark.skipif(
    not pytest.importorskip("yara", reason="yara-python not installed"),
    reason="yara-python not installed"
)
class TestYaraScanning:
    """Test YARA scanning functionality (requires yara-python)."""

    def test_compile_rules(self):
        from winforensics_mcp.parsers.yara_scanner import (
            compile_rules,
            get_default_rules_path,
            YARA_AVAILABLE,
        )

        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        rules_path = get_default_rules_path()
        rules = compile_rules([rules_path])

        # Rules should be compiled successfully
        assert rules is not None

    def test_scan_file_no_match(self):
        from winforensics_mcp.parsers.yara_scanner import scan_file, YARA_AVAILABLE

        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        # Create a harmless test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is a completely harmless test file with no malicious content.")
            temp_path = f.name

        try:
            result = scan_file(temp_path)

            assert "file" in result
            assert "matches" in result
            assert "match_count" in result
            assert "scan_time_ms" in result

            # Should not match any rules
            assert result["match_count"] == 0
            assert len(result["matches"]) == 0
        finally:
            Path(temp_path).unlink()

    def test_scan_file_result_structure(self):
        from winforensics_mcp.parsers.yara_scanner import scan_file, YARA_AVAILABLE

        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            temp_path = f.name

        try:
            result = scan_file(temp_path)

            # Verify result structure
            assert isinstance(result["file"], str)
            assert isinstance(result["file_size"], int)
            assert isinstance(result["matches"], list)
            assert isinstance(result["match_count"], int)
            assert isinstance(result["scan_time_ms"], float)
        finally:
            Path(temp_path).unlink()

    def test_scan_bytes(self):
        from winforensics_mcp.parsers.yara_scanner import scan_bytes, YARA_AVAILABLE

        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        # Scan harmless bytes
        data = b"This is harmless test data"
        result = scan_bytes(data, identifier="test_data")

        assert "identifier" in result
        assert "size" in result
        assert "matches" in result
        assert "match_count" in result

        assert result["identifier"] == "test_data"
        assert result["size"] == len(data)
        assert result["match_count"] == 0

    def test_scan_directory(self):
        from winforensics_mcp.parsers.yara_scanner import scan_directory, YARA_AVAILABLE

        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some test files
            for i in range(3):
                (Path(tmpdir) / f"test_{i}.txt").write_text(f"Harmless content {i}")

            result = scan_directory(tmpdir, file_pattern="*.txt")

            assert "directory" in result
            assert "files_scanned" in result
            assert "files_matched" in result
            assert "matches" in result

            assert result["files_scanned"] == 3
            assert result["files_matched"] == 0  # No malware in test files

    def test_scan_file_not_found(self):
        from winforensics_mcp.parsers.yara_scanner import scan_file, YARA_AVAILABLE

        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        with pytest.raises(FileNotFoundError):
            scan_file("/nonexistent/path/to/file.exe")

    def test_rule_caching(self):
        from winforensics_mcp.parsers.yara_scanner import (
            compile_rules,
            get_default_rules_path,
            _rule_cache,
            YARA_AVAILABLE,
        )

        if not YARA_AVAILABLE:
            pytest.skip("yara-python not installed")

        rules_path = get_default_rules_path()

        # Clear cache
        _rule_cache.clear()

        # Compile rules twice
        rules1 = compile_rules([rules_path], use_cache=True)
        rules2 = compile_rules([rules_path], use_cache=True)

        # Should use cached rules (same object)
        # Note: Can't directly compare yara.Rules objects, but cache should be populated
        assert len(_rule_cache) > 0


class TestYaraAvailabilityHandling:
    """Test graceful handling when yara-python is not available."""

    def test_availability_flag(self):
        from winforensics_mcp.parsers.yara_scanner import YARA_AVAILABLE

        # Should be a boolean
        assert isinstance(YARA_AVAILABLE, bool)

    def test_list_rules_without_yara(self):
        """list_rules should work even without yara-python installed."""
        from winforensics_mcp.parsers.yara_scanner import list_rules

        # This should not raise even if yara-python is not installed
        result = list_rules()
        assert "rule_files" in result
