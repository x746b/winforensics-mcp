"""Shared pytest fixtures and CLI options for APMX tests.

Supports --apmx-file and --expected-* options for parameterized integration tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("apmx", "APMX capture test options")
    group.addoption(
        "--apmx-file",
        default=None,
        help="Path to .apmx64/.apmx86 capture file for integration tests",
    )
    group.addoption(
        "--expected-pid",
        default=None,
        type=int,
        help="Expected target PID for injection regression test",
    )
    group.addoption(
        "--expected-shellcode-size",
        default=None,
        type=int,
        help="Expected shellcode size for injection regression test",
    )
    group.addoption(
        "--expected-technique",
        default=None,
        help="Expected injection technique name (e.g. 'Thread Local Storage')",
    )
    group.addoption(
        "--expected-snapshot-api",
        default=None,
        help="Expected snapshot API name (e.g. 'CreateToolhelp32Snapshot')",
    )
    group.addoption(
        "--expected-exec-api",
        default=None,
        help="Expected execution API name (e.g. 'CreateRemoteThread')",
    )
    group.addoption(
        "--expected-term-api",
        default=None,
        help="Expected termination API name (e.g. 'ExitProcess')",
    )
    group.addoption(
        "--expected-target-process",
        default=None,
        help="Expected target process name (e.g. 'notepad.exe')",
    )
    group.addoption(
        "--expected-alloc-size",
        default=None,
        type=int,
        help="Expected requested_alloc_size from VirtualAllocEx (e.g. 511)",
    )
    group.addoption(
        "--expected-aligned-size",
        default=None,
        type=int,
        help="Expected aligned_alloc_size from VirtualAllocEx post-value (e.g. 4096)",
    )


def _autodiscover_apmx() -> Path | None:
    tests_root = Path(__file__).resolve().parent
    for ext in ("*.apmx64", "*.apmx86"):
        files = sorted(tests_root.rglob(ext))
        if files:
            return files[0]
    return None


@pytest.fixture(scope="session")
def apmx_file(request: pytest.FixtureRequest) -> Path | None:
    """Resolved APMX capture path (from --apmx-file or autodiscovery)."""
    raw = request.config.getoption("--apmx-file")
    if raw:
        p = Path(raw)
        if not p.exists():
            pytest.fail(f"--apmx-file does not exist: {p}")
        return p
    return _autodiscover_apmx()


@pytest.fixture(scope="session")
def expected_answers(request: pytest.FixtureRequest) -> dict:
    return {
        "pid": request.config.getoption("--expected-pid"),
        "shellcode_size": request.config.getoption("--expected-shellcode-size"),
        "technique": request.config.getoption("--expected-technique"),
        "snapshot_api": request.config.getoption("--expected-snapshot-api"),
        "exec_api": request.config.getoption("--expected-exec-api"),
        "term_api": request.config.getoption("--expected-term-api"),
        "target_process": request.config.getoption("--expected-target-process"),
        "alloc_size": request.config.getoption("--expected-alloc-size"),
        "aligned_size": request.config.getoption("--expected-aligned-size"),
    }
