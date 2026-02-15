"""Regression tests for APMX injection captures.

Uses the ``apmx_file`` and ``expected_answers`` fixtures from conftest.py.
No hardcoded filenames or values — everything is passed via CLI options.

Usage:
    pytest tests/data/test_ghost_thread_regression.py \
        --apmx-file tests/data/Ghost-Thread.apmx64 \
        --expected-pid 16224 \
        --expected-shellcode-size 511 \
        --expected-technique "Thread Local Storage" \
        --expected-snapshot-api CreateToolhelp32Snapshot \
        --expected-exec-api CreateRemoteThread \
        --expected-term-api ExitProcess \
        --expected-target-process notepad.exe \
        --expected-alloc-size 511 \
        --expected-aligned-size 4096
"""

from __future__ import annotations

import pytest

from winforensics_mcp.parsers.api_monitor.apmx_parser import (
    detect_apmx_patterns,
    get_apmx_call_details,
    get_apmx_calls,
    get_apmx_injection_info,
    parse_apmx,
)


# ---------------------------------------------------------------------------
# Inference helpers (capture-agnostic logic)
# ---------------------------------------------------------------------------

def _infer_target_openprocess(apmx_path, process_index=0):
    """Return (pid, handle) from the first OpenProcess used for injection."""
    calls = get_apmx_calls(apmx_path, process_index=process_index, api_filter="OpenProcess", limit=20)
    assert calls["returned"] > 0, "OpenProcess not found in capture"

    idxs = [c["call_index"] for c in calls["calls"]]
    details = get_apmx_call_details(apmx_path, process_index=process_index, call_indices=idxs, limit=50)

    for c in details["calls"]:
        if c.get("api_name") != "OpenProcess":
            continue
        params = c.get("parameters", [])
        pid = None
        for p in params:
            if p.get("name") == "dwProcessId":
                pid = p.get("pre_value")
                break
        if pid is None and len(params) >= 4:
            pid = params[3].get("pre_value")
        handle = c.get("return_value") or params[0].get("post_value")
        if isinstance(pid, int) and pid > 0 and isinstance(handle, int) and handle > 0:
            return pid, handle

    raise AssertionError("could not infer target PID/handle from OpenProcess call details")


def _infer_injection_technique(apmx_path, process_index=0):
    """Return a technique label based on runtime API patterns."""
    fls_alloc = get_apmx_calls(apmx_path, process_index=process_index, api_filter="FlsAlloc", limit=5)
    fls_set = get_apmx_calls(apmx_path, process_index=process_index, api_filter="FlsSetValue", limit=5)
    early_fls = False
    if fls_alloc["returned"] > 0 and fls_alloc["calls"][0]["call_index"] < 200:
        early_fls = True
    if fls_set["returned"] > 0 and fls_set["calls"][0]["call_index"] < 200:
        early_fls = True

    exitp = get_apmx_calls(apmx_path, process_index=process_index, api_filter="ExitProcess", limit=5)
    has_exitprocess = exitp["returned"] > 0

    patterns = detect_apmx_patterns(apmx_path, process_index=process_index)
    ids = {d["pattern_id"] for d in patterns.get("details", [])}
    has_classic = "classic_injection" in ids

    if early_fls and has_exitprocess and has_classic:
        return "Thread Local Storage"
    if has_classic:
        return "Classic Process Injection"
    return "Unknown"


# ---------------------------------------------------------------------------
# Answer-validated regression tests
# ---------------------------------------------------------------------------

def _skip_if_no_file(apmx_file):
    if not apmx_file:
        pytest.skip("No --apmx-file provided and none discovered")


def _skip_if_no_answer(expected_answers, key):
    val = expected_answers.get(key)
    if val is None:
        pytest.skip(f"No --expected-{key.replace('_', '-')} provided")
    return val


def test_injection_technique(apmx_file, expected_answers):
    _skip_if_no_file(apmx_file)
    expected = _skip_if_no_answer(expected_answers, "technique")
    assert _infer_injection_technique(str(apmx_file)) == expected


def test_snapshot_api(apmx_file, expected_answers):
    _skip_if_no_file(apmx_file)
    expected = _skip_if_no_answer(expected_answers, "snapshot_api")
    snap = get_apmx_calls(str(apmx_file), process_index=0, api_filter=expected, limit=5)
    assert snap["returned"] > 0, f"{expected} not found in capture"


def test_target_pid(apmx_file, expected_answers):
    _skip_if_no_file(apmx_file)
    expected_pid = _skip_if_no_answer(expected_answers, "pid")
    pid, _handle = _infer_target_openprocess(str(apmx_file))
    assert pid == expected_pid


def test_shellcode_size(apmx_file, expected_answers):
    _skip_if_no_file(apmx_file)
    expected_size = _skip_if_no_answer(expected_answers, "shellcode_size")
    result = get_apmx_injection_info(str(apmx_file))
    assert result["chain_count"] >= 1
    chain = result["injection_chains"][0]
    assert chain["shellcode_size"] == expected_size


def test_execution_api(apmx_file, expected_answers):
    _skip_if_no_file(apmx_file)
    expected = _skip_if_no_answer(expected_answers, "exec_api")
    crt = get_apmx_calls(str(apmx_file), process_index=0, api_filter=expected, limit=5)
    assert crt["returned"] > 0, f"{expected} not found in capture"


def test_termination_api(apmx_file, expected_answers):
    _skip_if_no_file(apmx_file)
    expected = _skip_if_no_answer(expected_answers, "term_api")
    exitp = get_apmx_calls(str(apmx_file), process_index=0, api_filter=expected, limit=5)
    assert exitp["returned"] > 0, f"{expected} not found in capture"


# ---------------------------------------------------------------------------
# Structural regression tests (no expected values needed — just the file)
# ---------------------------------------------------------------------------

def test_process_index_regression(apmx_file):
    """P0: parse_apmx() must use 0-based process index."""
    _skip_if_no_file(apmx_file)
    result = parse_apmx(str(apmx_file))
    proc = result["processes"][0]
    assert proc["index"] == 0
    assert "process_index" not in proc
    assert "_raw_process_index" not in proc


def test_injection_info_structural(apmx_file):
    """P2: get_apmx_injection_info returns populated chains with required fields."""
    _skip_if_no_file(apmx_file)
    result = get_apmx_injection_info(str(apmx_file))
    assert "injection_chains" in result
    assert "chain_count" in result
    if result["chain_count"] > 0:
        chain = result["injection_chains"][0]
        assert "target_pid" in chain
        assert "shellcode_size" in chain
        assert "injection_technique" in chain
        assert "chain" in chain


def test_tls_pattern_detected(apmx_file, expected_answers):
    """P2: detect_apmx_patterns() includes tls_callback_execution when expected."""
    _skip_if_no_file(apmx_file)
    technique = expected_answers.get("technique")
    if technique != "Thread Local Storage":
        pytest.skip("TLS pattern test only applies when technique is 'Thread Local Storage'")
    result = detect_apmx_patterns(str(apmx_file))
    ids = [d["pattern_id"] for d in result["details"]]
    assert "tls_callback_execution" in ids


def test_target_process(apmx_file, expected_answers):
    """P1: get_apmx_injection_info extracts target process from Toolhelp decode."""
    _skip_if_no_file(apmx_file)
    expected = _skip_if_no_answer(expected_answers, "target_process")
    result = get_apmx_injection_info(str(apmx_file))
    assert result["chain_count"] >= 1
    chain = result["injection_chains"][0]
    actual = chain.get("target_process", "")
    assert actual.lower() == expected.lower(), f"Expected '{expected}', got '{actual}'"


def test_requested_alloc_size(apmx_file, expected_answers):
    """P1: get_apmx_injection_info reports correct requested_alloc_size."""
    _skip_if_no_file(apmx_file)
    expected = _skip_if_no_answer(expected_answers, "alloc_size")
    result = get_apmx_injection_info(str(apmx_file))
    assert result["chain_count"] >= 1
    chain = result["injection_chains"][0]
    assert chain.get("requested_alloc_size") == expected


def test_aligned_alloc_size(apmx_file, expected_answers):
    """P1: get_apmx_injection_info reports correct aligned_alloc_size."""
    _skip_if_no_file(apmx_file)
    expected = _skip_if_no_answer(expected_answers, "aligned_size")
    result = get_apmx_injection_info(str(apmx_file))
    assert result["chain_count"] >= 1
    chain = result["injection_chains"][0]
    assert chain.get("aligned_alloc_size") == expected


def test_flag_decoding_openprocess(apmx_file):
    """Flag decoding: OpenProcess dwDesiredAccess should have decoded_value."""
    _skip_if_no_file(apmx_file)
    calls = get_apmx_calls(str(apmx_file), api_filter="OpenProcess", limit=5)
    if calls["returned"] == 0:
        pytest.skip("No OpenProcess calls found")
    idx = calls["calls"][0]["call_index"]
    details = get_apmx_call_details(str(apmx_file), call_indices=[idx])
    for c in details["calls"]:
        for p in c.get("parameters", []):
            if p.get("name") == "dwDesiredAccess":
                assert "decoded_value" in p, "dwDesiredAccess should have decoded_value"
                assert "PROCESS_" in p["decoded_value"] or "0x" in p["decoded_value"]
                return
    pytest.skip("OpenProcess with named params not found in capture")


def test_time_range_filtering(apmx_file):
    """P3: time range filtering excludes calls outside the window."""
    _skip_if_no_file(apmx_file)
    # Get timestamps from a few calls to establish a time window
    details = get_apmx_call_details(str(apmx_file), limit=5)
    timestamps = [c["timestamp"] for c in details["calls"] if c.get("timestamp")]
    if len(timestamps) < 2:
        pytest.skip("Not enough timestamped calls")
    # Use second timestamp as start — should exclude first call
    start_ts = timestamps[1]
    all_calls = get_apmx_calls(str(apmx_file), limit=50000)
    filtered = get_apmx_calls(str(apmx_file), limit=50000, time_range_start=start_ts)
    assert filtered["returned"] < all_calls["returned"]
