import struct
from types import SimpleNamespace

from winforensics_mcp.parsers.pe_analyzer import (
    SPC_SP_OPUS_INFO_OID_DER,
    extract_spc_sp_opus_program_name,
    get_authenticode_info,
)


def der(tag: int, value: bytes) -> bytes:
    assert len(value) < 128
    return bytes((tag, len(value))) + value


def opus_info(name: str) -> bytes:
    program = der(0xA0, der(0x80, name.encode("utf-16-be")))
    return SPC_SP_OPUS_INFO_OID_DER + der(0x31, der(0x30, program))


def test_extract_spc_sp_opus_program_name():
    result = extract_spc_sp_opus_program_name(opus_info("Windows Update Assistant"))
    assert result == "Windows Update Assistant"


def test_get_authenticode_info_from_certificate_table(tmp_path):
    payload = opus_info("Signed Program")
    certificate = struct.pack("<IHH", len(payload) + 8, 0x200, 2) + payload
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"\x00" * 64 + certificate)
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(5)]
    directories[4] = SimpleNamespace(VirtualAddress=64, Size=len(certificate))
    pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories))

    result = get_authenticode_info(sample, pe)

    assert result["present"] is True
    assert result["program_name"] == "Signed Program"
    assert result["table_offset"] == "0x40"
