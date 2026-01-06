import pytest
from pathlib import Path


def test_imports():
    from winforensics_mcp import __version__
    assert __version__ == "0.1.0"


def test_config_imports():
    from winforensics_mcp.config import (
        IMPORTANT_EVENT_IDS,
        FORENSIC_REGISTRY_KEYS,
        ForensicsConfig,
    )
    
    assert "Security" in IMPORTANT_EVENT_IDS
    assert 4624 in IMPORTANT_EVENT_IDS["Security"]
    assert "persistence" in FORENSIC_REGISTRY_KEYS


def test_parser_imports():
    from winforensics_mcp.parsers import (
        EVTX_AVAILABLE,
        REGISTRY_AVAILABLE,
    )


def test_collector_imports():
    from winforensics_mcp.collectors import (
        ARTIFACT_PATHS,
        WINRM_AVAILABLE,
        PARAMIKO_AVAILABLE,
        SMB_AVAILABLE,
    )
    
    assert "evtx" in ARTIFACT_PATHS
    assert "registry" in ARTIFACT_PATHS


def test_server_imports():
    from winforensics_mcp.server import server, list_tools
    assert server is not None


def test_event_id_descriptions():
    from winforensics_mcp.parsers import get_event_id_description
    
    desc = get_event_id_description(4624, "Security")
    assert "Logon" in desc
    
    desc = get_event_id_description(4625, "Security")
    assert "Failed" in desc


def test_forensics_config():
    from winforensics_mcp.config import ForensicsConfig
    
    config = ForensicsConfig(
        artifacts_base=Path("/tmp/evidence"),
        output_dir=Path("/tmp/output"),
    )
    
    assert config.artifacts_base == Path("/tmp/evidence")
    assert config.max_evtx_results == 500
