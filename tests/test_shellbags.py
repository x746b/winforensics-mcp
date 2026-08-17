"""
ShellBags parser regression tests.

The shell item blobs below were captured from a real UsrClass.dat / NTUSER.DAT
pair so the tests are self-contained (no hive fixture files needed). Each one
pins down a specific way the parser has been observed to lose evidence.
"""
from __future__ import annotations

import pytest

from winforensics_mcp.parsers.shellbags_parser import (
    _decode_shell_item,
    _find_ntuser,
    _guid_label,
    _infer_user_profile,
    _join,
    _traverse_bagmru,
)

pyfwsi = pytest.importorskip("pyfwsi", reason="libfwsi-python required")


def h(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


# A file entry whose *raw* type byte is 0x74; libfwsi normalizes it to 0x31.
APPDATA = h(
    "820074001c00434653461600310000000000235b5838120041707044617461000000741a"
    "595e96dfd3488d671733bcee28bac5cdfadf9f6756418947c5c76bc0b67f400009000400"
    "efbe235b5838235b293a2e000000d47e01000000030000000000000000000000000000000"
    "9334b004100700070004400610074006100000042000000"
)

# A folder whose 8.3 short name is ONEPAS~1 and whose real name lives in the
# BEEF0004 extension block.
ONEPASSWORD = h(
    "7600310000000000235b943910004f4e455041537e3100005e0009000400efbe235b8939"
    "235b94392e000000e8b70100000002000000000000000000000000000000774c32004f00"
    "6e006500500061007300730077006f007200640020004d0061007300740065007200500061"
    "007300730000001 8000000".replace(" ", "")
)

# A 0x2e shell folder item: the Downloads known folder GUID at offset 4.
DOWNLOADS_DELEGATE = h(
    "3a002e8005398e082303024b98265d99428e115f260001002600efbe11000000b22e06c1"
    "a01cdc015b8a7ec4a01cdc0182083a34a21cdc0114000000"
)

# A 0xc3 network location holding a UNC path.
NETWORK_SHARE = h(
    "3000c301c55c5c50726f642d6e732d325c70726f647368617265004d6963726f736f6674"
    "204e6574776f726b000002000000"
)

# A property view with no name of its own (sits above the network location).
NAMELESS_PROPERTY_VIEW = h(
    "b3000000ad00bbaf933b9f000400000000002d000000315350537343e50abe43ad4f85e4"
    "69dc8633986e110000000b000000000b000000ffff00000000000041000000315350533"
    "0f125b7ef471a10a5f102608c9eebac250000000a000000001f0000000a000000500072"
    "006f0064002d006e0073002d0032000000000000002d000000315350533aa4bddeb3378"
    "34391e74498da2995ab1100000003000000001300000000000000000000000000000000"
    "000000"
)

# A property view whose raw type byte is 0x1f and whose bytes 4..20 begin with
# the My Computer GUID (20d04fe0). Dispatching on the raw byte decodes this as a
# root folder with a garbage GUID and throws the real name away.
PROPERTY_VIEW_RAW_1F = h(
    "9a001f50e04fd0200000000000000000000000000000000000000000000000001000010030"
    "0039002f00300033002f00320030003200350020002000300030003a00330034003a003100"
    "3800000000000800000019000000020000004f0054002000530074006100740069006f006e"
    "0020003300200069006e007400650072006e0061006c002000560050004e00000061002f00"
    "0000690070000000"
)


class TestClassTypeNormalization:
    """
    Dispatch must use libfwsi's normalized class_type, never the raw type byte.
    The raw byte carries flag bits that misreport the item's class.
    """

    def test_raw_0x74_is_a_file_entry(self):
        item = _decode_shell_item(APPDATA)
        assert item["raw_class_type"] == "0x74"
        assert item["class_type"] == "0x31"
        assert item["name"] == "AppData"
        assert item["folder_type"] == "folder"

    def test_raw_0x1f_property_view_is_not_a_root_folder(self):
        item = _decode_shell_item(PROPERTY_VIEW_RAW_1F)
        assert item["raw_class_type"] == "0x1f"
        assert item["class_type"] == "0x0"
        # The real name, not a bogus "Unknown GUID" root folder.
        assert item["name"] == "OT Station 3 internal VPN"
        assert item.get("guid") is None


class TestLongNames:
    """Long names come from the BEEF0004 extension block, not from offset guessing."""

    def test_long_name_beats_short_name(self):
        item = _decode_shell_item(ONEPASSWORD)
        assert item["name"] == "OnePassword MasterPass"
        assert item["short_name"] == "ONEPAS~1"
        assert item["folder_type"] == "folder"

    def test_extension_block_timestamps(self):
        item = _decode_shell_item(ONEPASSWORD)
        assert item["created_time"].startswith("2025-09-03T07:12:18")
        assert item["modified_time"].startswith("2025-09-03T07:12:40")


class TestKnownFolders:
    def test_0x2e_shell_folder_guid_resolves(self):
        item = _decode_shell_item(DOWNLOADS_DELEGATE)
        assert item["name"] == "Downloads"
        assert item["fs_anchor"] == "%USERPROFILE%\\Downloads"

    def test_computers_and_devices_label(self):
        # Previously mislabelled "Local Folder".
        name, anchor = _guid_label("f02c1a0d-be21-4350-88b0-7367fc96ef3c")
        assert name == "Computers and Devices"
        assert anchor is None

    def test_unknown_guid_keeps_the_guid(self):
        name, anchor = _guid_label("deadbeef-0000-0000-0000-000000000000")
        assert name == "{DEADBEEF-0000-0000-0000-000000000000}"
        assert anchor is None


class TestNetworkLocations:
    def test_unc_path_and_anchor(self):
        item = _decode_shell_item(NETWORK_SHARE)
        assert item["location"] == "\\\\Prod-ns-2\\prodshare"
        assert item["fs_anchor"] == "\\\\Prod-ns-2\\prodshare"
        assert item["description"] == "Microsoft Network"
        assert item["folder_type"] == "network"

    def test_nameless_property_view_is_transparent(self):
        item = _decode_shell_item(NAMELESS_PROPERTY_VIEW)
        assert item["name"] is None
        assert item["transparent"] is True


class TestJoin:
    def test_simple_join(self):
        assert _join("My Computer", "Documents") == "My Computer\\Documents"

    def test_no_double_separator(self):
        assert _join("My Computer\\", "Documents") == "My Computer\\Documents"

    def test_unc_name_is_absolute(self):
        # Must not become Computers and Devices\\\Prod-ns-2\prodshare
        assert _join("Computers and Devices", "\\\\Prod-ns-2\\prodshare") == (
            "\\\\Prod-ns-2\\prodshare"
        )

    def test_empty_parent(self):
        assert _join("", "My Computer") == "My Computer"
        assert _join(None, "My Computer") == "My Computer"


class FakeValue:
    def __init__(self, name, data):
        self._name = name
        self._data = data

    def name(self):
        return self._name

    def raw_data(self):
        return self._data


class FakeKey:
    """Minimal stand-in for a python-registry key holding a BagMRU node."""

    def __init__(self, items, node_slot=None):
        # items: {value_name: (blob, child_FakeKey_or_None)}
        self._items = items
        self._node_slot = node_slot

    def values(self):
        out = [FakeValue(n, blob) for n, (blob, _) in self._items.items()]
        if self._node_slot is not None:
            out.append(FakeValue("NodeSlot", b""))
        return out

    def subkey(self, name):
        if name not in self._items or self._items[name][1] is None:
            raise KeyError(name)
        return self._items[name][1]

    def value(self, name):
        if name == "NodeSlot" and self._node_slot is not None:
            return FakeValue("NodeSlot", self._node_slot)
        raise KeyError(name)


class FakeSlotValue(FakeValue):
    def value(self):
        return self._data


class FakeKeyWithSlot(FakeKey):
    def value(self, name):
        if name == "NodeSlot" and self._node_slot is not None:
            return FakeSlotValue("NodeSlot", self._node_slot)
        raise KeyError(name)


class TestTraversalDoesNotPruneSubtrees:
    """
    An item that fails to decode, or that has no name, must not stop the walk.
    Pruning on decode failure silently deleted the whole network-share branch.
    """

    def test_undecodable_parent_still_yields_children(self):
        child = FakeKeyWithSlot({"0": (ONEPASSWORD, None)}, node_slot=8)
        # b"\x02\x00" is a 2-byte blob that cannot produce a shell item.
        root = FakeKeyWithSlot({"0": (b"\x02\x00", child)})

        results = []
        _traverse_bagmru(
            root, "", None, results, {8: "2025-09-03T07:28:49+00:00"},
            None, 100, "UsrClass.dat", "C:\\Users\\steve",
        )

        paths = [r["path"] for r in results]
        assert any("OnePassword MasterPass" in p for p in paths), (
            f"child lost when parent failed to decode: {paths}"
        )

    def test_transparent_node_does_not_appear_in_child_paths(self):
        share = FakeKeyWithSlot({"0": (NETWORK_SHARE, None)}, node_slot=11)
        propview = FakeKeyWithSlot({"0": (NAMELESS_PROPERTY_VIEW, share)})
        root = FakeKeyWithSlot({"0": (NAMELESS_PROPERTY_VIEW, propview)})

        results = []
        _traverse_bagmru(
            root, "Computers and Devices", None, results,
            {11: "2025-09-03T07:32:23+00:00"}, None, 100,
            "UsrClass.dat", "C:\\Users\\steve",
        )

        paths = [r["path"] for r in results]
        assert "\\\\Prod-ns-2\\prodshare" in paths, paths
        assert not any("unnamed" in p for p in paths), paths

    def test_filtered_out_parent_still_yields_matching_child(self):
        child = FakeKeyWithSlot({"0": (ONEPASSWORD, None)}, node_slot=8)
        root = FakeKeyWithSlot({"0": (APPDATA, child)})

        results = []
        _traverse_bagmru(
            root, "", None, results, {}, "OnePassword", 100,
            "UsrClass.dat", "C:\\Users\\steve",
        )

        paths = [r["path"] for r in results]
        assert paths == ["AppData\\OnePassword MasterPass"], paths

    def test_recursion_depth_is_bounded(self):
        # A key that is its own child must not recurse forever.
        loop = FakeKeyWithSlot({})
        loop._items = {"0": (APPDATA, loop)}

        results = []
        _traverse_bagmru(
            loop, "", None, results, {}, None, 10_000,
            "UsrClass.dat", None,
        )
        assert len(results) <= 65


class TestResolvedPaths:
    def test_known_folder_anchor_expands_user_profile(self):
        child = FakeKeyWithSlot({"0": (ONEPASSWORD, None)}, node_slot=8)
        root = FakeKeyWithSlot({"0": (DOWNLOADS_DELEGATE, child)})

        results = []
        _traverse_bagmru(
            root, "My Computer", None, results, {}, None, 100,
            "UsrClass.dat", "C:\\Users\\steve",
        )

        by_path = {r["path"]: r for r in results}
        leaf = by_path["My Computer\\Downloads\\OnePassword MasterPass"]
        assert leaf["resolved_path"] == (
            "C:\\Users\\steve\\Downloads\\OnePassword MasterPass"
        )


class TestProfileDiscovery:
    def test_infer_profile_from_usrclass(self, tmp_path):
        p = tmp_path / "Users" / "steve" / "AppData" / "Local" / "Microsoft" / "Windows"
        p.mkdir(parents=True)
        hive = p / "UsrClass.dat"
        hive.write_bytes(b"")
        assert _infer_user_profile(hive) == "C:\\Users\\steve"

    def test_infer_profile_from_ntuser(self, tmp_path):
        p = tmp_path / "Users" / "admin"
        p.mkdir(parents=True)
        hive = p / "NTUSER.DAT"
        hive.write_bytes(b"")
        assert _infer_user_profile(hive) == "C:\\Users\\admin"

    def test_find_ntuser_next_to_profile(self, tmp_path):
        profile = tmp_path / "Users" / "steve"
        win = profile / "AppData" / "Local" / "Microsoft" / "Windows"
        win.mkdir(parents=True)
        usrclass = win / "UsrClass.dat"
        usrclass.write_bytes(b"")
        ntuser = profile / "NTUSER.DAT"
        ntuser.write_bytes(b"")

        assert _find_ntuser(usrclass) == ntuser

    def test_find_ntuser_returns_none_for_ntuser_input(self, tmp_path):
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"")
        assert _find_ntuser(ntuser) is None

    def test_find_ntuser_missing(self, tmp_path):
        win = tmp_path / "Users" / "steve" / "AppData" / "Local" / "Microsoft" / "Windows"
        win.mkdir(parents=True)
        usrclass = win / "UsrClass.dat"
        usrclass.write_bytes(b"")
        assert _find_ntuser(usrclass) is None


class TestMalformedInput:
    def test_short_blob(self):
        item = _decode_shell_item(b"\x01")
        assert item["folder_type"] == "unknown"
        assert "decode_error" in item

    def test_empty_blob(self):
        item = _decode_shell_item(b"")
        assert item["folder_type"] == "unknown"
