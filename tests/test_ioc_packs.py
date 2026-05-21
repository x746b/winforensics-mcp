"""Tests for behavioral IoC pack loading and hunting."""

from __future__ import annotations

import json


def test_list_ioc_packs_includes_impacket():
    from winforensics_mcp.ioc_packs import list_ioc_packs

    result = list_ioc_packs()
    pack_ids = {pack["id"] for pack in result["packs"]}

    assert "impacket-iocs" in pack_ids


def test_load_impacket_ioc_pack_metadata():
    from winforensics_mcp.ioc_packs import load_ioc_pack

    pack = load_ioc_pack("impacket-iocs")

    assert pack["id"] == "impacket-iocs"
    assert pack["license"] == "GPL-2.0"
    assert pack["upstream"] == "https://github.com/ThatTotallyRealMyth/Impacket-IoCs"
    assert len(pack["rules"]) >= 65


def test_impacket_pack_json_is_valid():
    from importlib.resources import files

    pack_file = files("winforensics_mcp").joinpath(
        "ioc_packs", "impacket-iocs", "pack.json"
    )

    pack = json.loads(pack_file.read_text(encoding="utf-8"))
    assert pack["id"] == "impacket-iocs"


def test_impacket_ioc_pack_covers_expanded_references():
    from winforensics_mcp.ioc_packs import load_ioc_pack

    pack = load_ioc_pack("impacket-iocs")
    rule_ids = {rule["id"] for rule in pack["rules"]}

    assert "impacket.dcerpc.auth_context_79231" in rule_ids
    assert "impacket.secretsdump.drsbind_extcaps_all" in rule_ids
    assert "impacket.badsuccessor.dmsa_defaults" in rule_ids
    assert "impacket.wmi.ntlmlogin_local_namespace_null_locale" in rule_ids
    assert "impacket.dcom.iremunknown_single_public_ref_release" in rule_ids


def test_hunt_ioc_pack_finds_text_artifact(tmp_path):
    from winforensics_mcp.ioc_packs import hunt_ioc_pack

    log = tmp_path / "sherlock_notes.md"
    log.write_text(
        "PipeName: \\\\RemCom_communicaton\n"
        "CommandLine: certutil -decode C:\\\\Temp\\\\payload.b64 C:\\\\Temp\\\\payload.exe\n"
        "CommandLine: certutil -hashfile C:\\\\Temp\\\\payload.exe MD5\n",
        encoding="utf-8",
    )

    result = hunt_ioc_pack(
        tmp_path,
        pack="impacket-iocs",
        scan_pcap=False,
    )

    matched_ids = {finding["id"] for finding in result["findings"]}
    assert result["found"] is True
    assert "impacket.psexec.remcom_pipes" in matched_ids
    assert "impacket.mssqlshell.certutil_upload" in matched_ids


def test_hunt_ioc_pack_finds_utf16le_export(tmp_path):
    from winforensics_mcp.ioc_packs import hunt_ioc_pack

    log = tmp_path / "powershell_export.txt"
    log.write_bytes("PipeName: \\\\RemCom_communicaton\n".encode("utf-16-le"))

    result = hunt_ioc_pack(
        tmp_path,
        pack="impacket-iocs",
        scan_pcap=False,
    )

    matched_ids = {finding["id"] for finding in result["findings"]}
    assert "impacket.psexec.remcom_pipes" in matched_ids


def test_hunt_ioc_pack_finds_expanded_protocol_exports(tmp_path):
    from winforensics_mcp.ioc_packs import hunt_ioc_pack

    log = tmp_path / "decoded_rpc_ldap.txt"
    log.write_text(
        "DRSBind DRSUAPI dwExtCaps: 0xffffffff Pid: 0\n"
        "OpenSCManagerW lpMachineName: DUMMY\n"
        "auth_context_id: 79231\n"
        "objectClass: msDS-DelegatedManagedServiceAccount "
        "cn: dMSA-ABC123DE msDS-DelegatedMSAState: 2 "
        "msDS-SupportedEncryptionTypes: 28\n",
        encoding="utf-8",
    )

    result = hunt_ioc_pack(
        tmp_path,
        pack="impacket-iocs",
        scan_pcap=False,
    )

    matched_ids = {finding["id"] for finding in result["findings"]}
    assert "impacket.secretsdump.drsbind_extcaps_all" in matched_ids
    assert "impacket.scmr.dummy_machine_name" in matched_ids
    assert "impacket.dcerpc.auth_context_79231" in matched_ids
    assert "impacket.badsuccessor.dmsa_defaults" in matched_ids


def test_hunt_ioc_pack_finds_ntlmrelayx_computer_account_export(tmp_path):
    from winforensics_mcp.ioc_packs import hunt_ioc_pack

    log = tmp_path / "ldap_changes.jsonl"
    log.write_text(
        '{"sAMAccountName": "ABCDEFGH$", "dNSHostName": "ABCDEFGH.example.local"}\n',
        encoding="utf-8",
    )

    result = hunt_ioc_pack(
        tmp_path,
        pack="impacket-iocs",
        scan_pcap=False,
    )

    matched_ids = {finding["id"] for finding in result["findings"]}
    assert "impacket.ntlmrelayx.ldap_computer_random_name" in matched_ids


def test_hunt_ioc_pack_ignores_minified_javascript_locale_keys(tmp_path):
    from winforensics_mcp.ioc_packs import hunt_ioc_pack

    script = tmp_path / "fabric-chunk_vendors.js"
    script.write_text(
        'CN:["H","hB","hb","h"],LV:["H","hB","hb","h"],'
        'function getValue(){return "NOTANIOC$"};\n',
        encoding="utf-8",
    )

    result = hunt_ioc_pack(
        tmp_path,
        pack="impacket-iocs",
        scan_pcap=False,
    )

    matched_ids = {finding["id"] for finding in result["findings"]}
    assert "impacket.ntlmrelayx.ldap_computer_random_name" not in matched_ids


def test_hunt_ioc_pack_finds_sherlock_wmiexec_markdown_snippet(tmp_path):
    from winforensics_mcp.ioc_packs import hunt_ioc_pack

    notes = tmp_path / "Holmes 2025 3 - The Enduring Echo.md"
    notes.write_text(
        "Process creation events showed `cmd.exe /Q /c <command> "
        "1> \\\\127.0.0.1\\ADMIN$\\__<timestamp> 2>&1`, "
        "the signature pattern of Impacket's wmiexec.py.\n",
        encoding="utf-8",
    )

    result = hunt_ioc_pack(
        tmp_path,
        pack="impacket-iocs",
        scan_pcap=False,
    )

    matched_ids = {finding["id"] for finding in result["findings"]}
    assert "impacket.dcomexec.loopback_admin_output" in matched_ids
