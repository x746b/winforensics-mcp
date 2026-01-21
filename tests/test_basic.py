"""
Basic smoke tests for winforensics-mcp.

These tests verify that all modules can be imported and basic functionality works.
They don't require actual forensic artifacts to run.
"""
import pytest
from pathlib import Path


class TestVersionAndMetadata:
    """Test package metadata."""

    def test_version(self):
        from winforensics_mcp import __version__
        assert __version__ == "0.3.0"

    def test_author(self):
        from winforensics_mcp import __author__
        assert __author__ == "xtk"


class TestConfigImports:
    """Test config module imports."""

    def test_important_event_ids(self):
        from winforensics_mcp.config import IMPORTANT_EVENT_IDS
        assert "Security" in IMPORTANT_EVENT_IDS
        assert 4624 in IMPORTANT_EVENT_IDS["Security"]
        assert 4625 in IMPORTANT_EVENT_IDS["Security"]

    def test_forensic_registry_keys(self):
        from winforensics_mcp.config import FORENSIC_REGISTRY_KEYS
        assert "persistence" in FORENSIC_REGISTRY_KEYS
        assert "services" in FORENSIC_REGISTRY_KEYS

    def test_limits(self):
        from winforensics_mcp.config import (
            MAX_EVTX_RESULTS,
            MAX_REGISTRY_RESULTS,
            MAX_PREFETCH_RESULTS,
            MAX_AMCACHE_RESULTS,
            MAX_TIMELINE_RESULTS,
            MAX_MFT_RESULTS,
            MAX_USN_RESULTS,
        )
        # All limits should be positive integers
        assert all(isinstance(x, int) and x > 0 for x in [
            MAX_EVTX_RESULTS,
            MAX_REGISTRY_RESULTS,
            MAX_PREFETCH_RESULTS,
            MAX_AMCACHE_RESULTS,
            MAX_TIMELINE_RESULTS,
            MAX_MFT_RESULTS,
            MAX_USN_RESULTS,
        ])


class TestParserImports:
    """Test parser module imports."""

    def test_evtx_parser_imports(self):
        from winforensics_mcp.parsers import (
            get_evtx_events,
            list_evtx_files,
            get_evtx_stats,
            search_security_events,
            get_event_id_description,
            EVTX_AVAILABLE,
        )
        assert isinstance(EVTX_AVAILABLE, bool)

    def test_registry_parser_imports(self):
        from winforensics_mcp.parsers import (
            get_registry_key,
            search_registry_values,
            get_run_keys,
            get_services,
            get_usb_devices,
            get_user_accounts,
            get_network_interfaces,
            get_system_info,
            REGISTRY_AVAILABLE,
        )
        assert isinstance(REGISTRY_AVAILABLE, bool)

    def test_pe_analyzer_imports(self):
        from winforensics_mcp.parsers import (
            analyze_pe,
            PEFILE_AVAILABLE,
        )
        assert isinstance(PEFILE_AVAILABLE, bool)

    def test_prefetch_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_prefetch_file,
            parse_prefetch_directory,
            PYSCCA_AVAILABLE,
        )
        assert isinstance(PYSCCA_AVAILABLE, bool)

    def test_amcache_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_amcache,
            search_amcache_by_sha1,
            get_amcache_executables,
        )

    def test_srum_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_srum,
            PYESEDB_AVAILABLE,
        )
        assert isinstance(PYESEDB_AVAILABLE, bool)

    def test_mft_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_mft,
            find_timestomped_files,
            MFT_AVAILABLE,
        )
        assert isinstance(MFT_AVAILABLE, bool)

    def test_usn_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_usn_journal,
            find_deleted_files,
        )

    def test_browser_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_browser_history,
            get_browser_downloads,
        )

    def test_lnk_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_lnk_file,
            parse_lnk_directory,
            get_recent_files,
            PYLNK_AVAILABLE,
        )
        assert isinstance(PYLNK_AVAILABLE, bool)

    def test_shellbags_parser_imports(self):
        from winforensics_mcp.parsers import (
            parse_shellbags,
            find_suspicious_folders,
        )

    def test_csv_ingestor_imports(self):
        from winforensics_mcp.parsers import (
            ingest_csv,
            query_mftecmd_csv,
            query_pecmd_csv,
            query_amcache_csv,
        )


class TestOrchestratorImports:
    """Test orchestrator module imports."""

    def test_execution_tracker_imports(self):
        from winforensics_mcp.orchestrators import (
            investigate_execution,
            find_artifact_paths,
        )

    def test_timeline_builder_imports(self):
        from winforensics_mcp.orchestrators import (
            build_timeline,
            find_timeline_artifacts,
        )

    def test_ioc_hunter_imports(self):
        from winforensics_mcp.orchestrators import hunt_ioc

    def test_user_activity_investigator_imports(self):
        from winforensics_mcp.orchestrators import investigate_user_activity

    def test_package_level_exports(self):
        from winforensics_mcp import (
            investigate_execution,
            investigate_user_activity,
            build_timeline,
            hunt_ioc,
            find_artifact_paths,
        )


class TestCollectorImports:
    """Test collector module imports."""

    def test_collector_imports(self):
        from winforensics_mcp.collectors import (
            ARTIFACT_PATHS,
            WINRM_AVAILABLE,
            PARAMIKO_AVAILABLE,
            SMB_AVAILABLE,
        )
        assert "evtx" in ARTIFACT_PATHS
        assert "registry" in ARTIFACT_PATHS
        assert isinstance(WINRM_AVAILABLE, bool)
        assert isinstance(PARAMIKO_AVAILABLE, bool)
        assert isinstance(SMB_AVAILABLE, bool)


class TestServerImports:
    """Test server module imports."""

    def test_server_imports(self):
        from winforensics_mcp.server import server, list_tools
        assert server is not None


class TestEventIdDescriptions:
    """Test event ID description lookups."""

    def test_security_event_descriptions(self):
        from winforensics_mcp.parsers import get_event_id_description

        # Test known event IDs
        assert "Logon" in get_event_id_description(4624, "Security")
        assert "Failed" in get_event_id_description(4625, "Security")
        assert "Process" in get_event_id_description(4688, "Security")

    def test_unknown_event_id(self):
        from winforensics_mcp.parsers import get_event_id_description

        # Unknown event ID should return something (not crash)
        result = get_event_id_description(99999, "Security")
        assert isinstance(result, str)


class TestForensicsConfig:
    """Test ForensicsConfig dataclass."""

    def test_config_creation(self):
        from winforensics_mcp.config import ForensicsConfig

        config = ForensicsConfig(
            artifacts_base=Path("/tmp/evidence"),
            output_dir=Path("/tmp/output"),
        )

        assert config.artifacts_base == Path("/tmp/evidence")
        assert config.output_dir == Path("/tmp/output")

    def test_config_defaults(self):
        from winforensics_mcp.config import ForensicsConfig

        config = ForensicsConfig(
            artifacts_base=Path("/tmp/evidence"),
            output_dir=Path("/tmp/output"),
        )

        # Check default limits are set
        assert config.max_evtx_results > 0
        assert config.max_registry_results > 0
