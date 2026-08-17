"""
ShellBags Parser Module

Parses Windows ShellBags to extract folder navigation history. ShellBags reveal
which folders a user browsed in Windows Explorer, including the *interior* of ZIP
archives and UNC network shares.

Two BagMRU roots exist per user profile and they hold different namespaces:

    UsrClass.dat  ->  Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU
    NTUSER.DAT    ->  Software\\Microsoft\\Windows\\Shell\\BagMRU

Both are parsed. Shell items are decoded with libfwsi (pyfwsi), which resolves
long names out of BEEF0004 extension blocks rather than guessing at offsets.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

try:
    import pyfwsi
    FWSI_AVAILABLE = True
except ImportError:
    FWSI_AVAILABLE = False

from ..config import MAX_REGISTRY_RESULTS

USRCLASS_BAGMRU = "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
USRCLASS_BAGS = "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags"
NTUSER_BAGMRU = "Software\\Microsoft\\Windows\\Shell\\BagMRU"
NTUSER_BAGS = "Software\\Microsoft\\Windows\\Shell\\Bags"


def check_registry_available() -> None:
    """Raise error if python-registry library not available"""
    if not REGISTRY_AVAILABLE:
        raise ImportError(
            "python-registry library not installed. Install with: pip install python-registry"
        )


def check_fwsi_available() -> None:
    """Raise error if libfwsi bindings are not available"""
    if not FWSI_AVAILABLE:
        raise ImportError(
            "libfwsi-python not installed. Install with: pip install libfwsi-python"
        )


# Shell folder / known folder GUIDs.
# Keys are lowercase without braces (the form libfwsi returns).
# Value is (display_name, filesystem_anchor_or_None).
# "%USERPROFILE%" is expanded from the hive's profile directory when known.
KNOWN_GUIDS: dict[str, tuple[str, Optional[str]]] = {
    # Computer / namespace roots
    "20d04fe0-3aea-1069-a2d8-08002b30309d": ("My Computer", None),
    "0ac0837c-bbf8-452a-850d-79d08e667ca7": ("Computer", None),
    "5b934b42-522b-4c34-bbfe-37a3ef7b9c90": ("This Device", None),
    "f874310e-b6b7-47dc-bc84-b9e6b38f5903": ("Home", None),
    "679f85cb-0220-4080-b29b-5540cc05aab6": ("Quick Access", None),
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": ("Libraries", None),
    "645ff040-5081-101b-9f08-00aa002f954e": ("Recycle Bin", None),
    "4234d49b-0245-4df3-b780-3893943456e1": ("Applications", None),
    # Network
    "208d2c60-3aea-1069-a2d7-08002b30309d": ("Network", None),
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": ("Computers and Devices", None),
    "d20beec4-5ca8-4905-ae3b-bf251ea09b53": ("Network", None),
    "de61d971-5ebc-4f02-a3a9-6c82895e5c04": ("Add Network Location", None),
    # User profile
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": ("User Profile", "%USERPROFILE%"),
    "5e6c858f-0e22-4760-9afe-ea3317b67173": ("User Profile", "%USERPROFILE%"),
    "9b74b6a3-0dfd-4f11-9e78-5f7800f2e772": ("User Name", "%USERPROFILE%"),
    # Desktop
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": ("Desktop", "%USERPROFILE%\\Desktop"),
    "754ac886-df64-4cba-86b5-f7fbf4fbcef5": ("Desktop", "%USERPROFILE%\\Desktop"),
    # Documents
    "450d8fba-ad25-11d0-98a8-0800361b1103": ("My Documents", "%USERPROFILE%\\Documents"),
    "d3162b92-9365-467a-956b-92703aca08af": ("Documents", "%USERPROFILE%\\Documents"),
    "fdd39ad0-238f-46af-adb4-6c85480369c7": ("Documents", "%USERPROFILE%\\Documents"),
    "7b0db17d-9cd2-4a93-9733-46cc89022e7c": ("Documents Library", None),
    # Downloads
    "374de290-123f-4565-9164-39c4925e467b": ("Downloads", "%USERPROFILE%\\Downloads"),
    "088e3905-0323-4b02-9826-5d99428e115f": ("Downloads", "%USERPROFILE%\\Downloads"),
    # Pictures
    "33e28130-4e1e-4676-835a-98395c3bc3bb": ("Pictures", "%USERPROFILE%\\Pictures"),
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": ("Pictures", "%USERPROFILE%\\Pictures"),
    "3add1653-eb32-4cb0-bbd7-dfa0abb5acca": ("Pictures", "%USERPROFILE%\\Pictures"),
    "a990ae9f-a03b-4e80-94bc-9912d7504104": ("Pictures Library", None),
    # Music
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": ("Music", "%USERPROFILE%\\Music"),
    "4bd8d571-6d19-48d3-be97-422220080e43": ("Music", "%USERPROFILE%\\Music"),
    "2112ab0a-c86a-4ffe-a368-0de96e47012e": ("Music Library", None),
    # Videos
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": ("Videos", "%USERPROFILE%\\Videos"),
    "a0953c92-50dc-43bf-be83-3742fed03c9c": ("Videos", "%USERPROFILE%\\Videos"),
    "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": ("Videos", "%USERPROFILE%\\Videos"),
    "491e922f-5643-4af4-a7eb-4e7a138d8174": ("Videos Library", None),
    # AppData
    "dffacdc5-679f-4156-8947-c5c76bc0b67f": ("Local AppData", "%USERPROFILE%\\AppData\\Local"),
    "3eb685db-65f9-4cf6-a03a-e3ef65729f3d": ("Roaming AppData", "%USERPROFILE%\\AppData\\Roaming"),
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": ("System32", "C:\\Windows\\System32"),
    "d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27": ("System32 (x86)", "C:\\Windows\\SysWOW64"),
    "f38bf404-1d43-42f2-9305-67de0b28fc23": ("Windows", "C:\\Windows"),
    "905e63b6-c1bf-494e-b29c-65b732d3d21a": ("Program Files", "C:\\Program Files"),
    "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97": ("ProgramData", "C:\\ProgramData"),
    # Control panel / misc
    "21ec2020-3aea-1069-a2dd-08002b30309d": ("Control Panel", None),
    "26ee0668-a00a-44d7-9371-beb064c98683": ("Control Panel", None),
    "d20ea4e1-3957-11d2-a40b-0c5020524153": ("Administrative Tools", None),
    "1f3427c8-5c10-4210-aa03-2ee45287d668": ("User Pinned", None),
    "9e3995ab-1f9c-4f13-b827-48b24b6c7174": ("User Pinned", None),
    "871c5380-42a0-1069-a2ea-08002b30309d": ("Internet Explorer", None),
    "fbf23b42-e3f0-101b-8488-00aa003e56f8": ("Internet Explorer", None),
}


def _normalize_guid(guid: Optional[str]) -> Optional[str]:
    """Normalize a GUID to lowercase without braces"""
    if not guid:
        return None
    return guid.strip("{}").lower()


def _guid_label(guid: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve a shell folder GUID to (display_name, filesystem_anchor).

    Unknown GUIDs are rendered as ``{guid}`` rather than a generic placeholder so
    distinct unknown namespaces stay distinguishable in the output.
    """
    norm = _normalize_guid(guid)
    if not norm:
        return None, None
    known = KNOWN_GUIDS.get(norm)
    if known:
        return known[0], known[1]
    return "{%s}" % norm.upper(), None


def _parse_guid_le(data: bytes) -> Optional[str]:
    """Parse a little-endian 16-byte GUID into lowercase dashed form"""
    if len(data) < 16:
        return None
    d1, d2, d3 = struct.unpack("<IHH", data[:8])
    d4 = data[8:16]
    return "%08x-%04x-%04x-%s-%s" % (
        d1, d2, d3, d4[:2].hex(), d4[2:].hex()
    )


def _format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Format a datetime to ISO string, assuming UTC when naive"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _safe_attr(obj: Any, name: str) -> Any:
    """Read an attribute, swallowing libfwsi decode errors"""
    try:
        return getattr(obj, name)
    except Exception:
        return None


def _safe_call(obj: Any, name: str) -> Any:
    """Call a getter, swallowing libfwsi decode errors"""
    try:
        return getattr(obj, name)()
    except Exception:
        return None


def _extension_block_info(obj: Any) -> dict[str, Any]:
    """
    Pull long name and timestamps out of a shell item's extension blocks.

    The BEEF0004 file entry extension block carries the *long* (non-8.3) name
    plus creation and access times. This is the authoritative source for names
    like "OnePassword MasterPass" whose short name is "ONEPAS~1".
    """
    info: dict[str, Any] = {}
    count = _safe_attr(obj, "number_of_extension_blocks") or 0

    for i in range(count):
        try:
            block = obj.get_extension_block(i)
        except Exception:
            continue

        long_name = _safe_attr(block, "long_name")
        if long_name and "long_name" not in info:
            info["long_name"] = long_name

        localized = _safe_attr(block, "localized_name")
        if localized and "localized_name" not in info:
            info["localized_name"] = localized

        created = _safe_call(block, "get_creation_time")
        if created and "created_time" not in info:
            info["created_time"] = _format_datetime(created)

        accessed = _safe_call(block, "get_access_time")
        if accessed and "accessed_time" not in info:
            info["accessed_time"] = _format_datetime(accessed)

        ref = _safe_attr(block, "file_reference")
        if ref and "mft_reference" not in info:
            info["mft_reference"] = str(ref)

    return info


def _decode_shell_item(data: bytes) -> dict[str, Any]:
    """
    Decode a single shell item blob.

    Always returns a dict. A blob that cannot be named still yields an entry with
    ``name`` set to a synthetic placeholder, because BagMRU children hang off the
    registry key regardless of whether the parent item decoded -- dropping an
    undecodable item would prune its entire subtree.
    """
    result: dict[str, Any] = {"item_size": len(data)}

    if len(data) < 3:
        result["name"] = "<truncated>"
        result["folder_type"] = "unknown"
        result["decode_error"] = "shell item shorter than 3 bytes"
        return result

    if not FWSI_AVAILABLE:
        result["name"] = "<no libfwsi>"
        result["folder_type"] = "unknown"
        result["decode_error"] = "libfwsi-python not installed"
        return result

    # Dispatch on libfwsi's *normalized* class type, never on the raw type byte.
    # The raw byte carries flag bits that make it lie about the item's class:
    # 0x74 is really a 0x31 file entry, and 0x3a / 0xb5 / 0x1f property views all
    # normalize to 0x00 -- reading the raw byte would decode that last one as a
    # root folder and lose the item.
    result["raw_class_type"] = hex(data[2])
    try:
        probe = pyfwsi.item()
        probe.copy_from_byte_stream(data)
        class_type = probe.class_type
    except Exception as exc:
        result["name"] = "<undecodable>"
        result["folder_type"] = "unknown"
        result["decode_error"] = str(exc)
        return result

    result["class_type"] = hex(class_type)

    # Class type 0x2e carries a shell folder GUID at offset 4. libfwsi's Python
    # bindings do not surface this one, so decode it directly.
    if class_type == 0x2E:
        guid = _parse_guid_le(data[4:20])
        name, anchor = _guid_label(guid)
        result["guid"] = guid
        result["name"] = name or "<shell folder>"
        result["folder_type"] = "known_folder"
        if anchor:
            result["fs_anchor"] = anchor
        return result

    # Dispatch on class type to the matching libfwsi item class.
    if class_type == 0x1F:
        cls, kind = pyfwsi.root_folder, "root"
    elif class_type == 0x2F:
        cls, kind = pyfwsi.volume, "volume"
    elif class_type == 0x00:
        cls, kind = pyfwsi.users_property_view, "property_view"
    elif class_type == 0x52:
        cls, kind = pyfwsi.compressed_folder, "archive"
    elif class_type & 0x70 == 0x40 or class_type == 0xC3:
        cls, kind = pyfwsi.network_location, "network"
    elif class_type & 0x70 == 0x30:
        cls, kind = pyfwsi.file_entry, "file_entry"
    else:
        cls, kind = None, "unknown"

    if cls is None:
        result["name"] = None
        result["transparent"] = True
        result["folder_type"] = kind
        return result

    try:
        item = cls()
        item.copy_from_byte_stream(data)
    except Exception as exc:
        result["name"] = "<undecoded %s>" % hex(class_type)
        result["folder_type"] = kind
        result["decode_error"] = str(exc)
        return result

    result["folder_type"] = kind
    result.update(_extension_block_info(item))

    # Directory vs file, from the shell item class type low bits.
    if kind == "file_entry":
        result["folder_type"] = "folder" if class_type & 0x01 else "file"

    # Name resolution, in order of trustworthiness.
    short_name = _safe_attr(item, "name")
    if short_name:
        result["short_name"] = short_name

    name = (
        result.get("long_name")
        or result.get("localized_name")
        or short_name
    )

    # GUID-bearing items (roots, volumes, property views).
    guid = (
        _safe_attr(item, "shell_folder_identifier")
        or _safe_attr(item, "known_folder_identifier")
    )
    if guid:
        result["guid"] = guid
        label, anchor = _guid_label(guid)
        if anchor:
            result["fs_anchor"] = anchor
        if not name:
            name = label

    # Network locations: the UNC path is itself the anchor.
    location = _safe_attr(item, "location")
    if location:
        result["location"] = location
        result["fs_anchor"] = location
        if not name:
            name = location
    description = _safe_attr(item, "description")
    if description:
        result["description"] = description

    # Volumes anchor the resolved path at a drive letter.
    if kind == "volume" and short_name:
        result["fs_anchor"] = short_name.rstrip("\\")

    mtime = _safe_call(item, "get_modification_time")
    if mtime:
        result["modified_time"] = _format_datetime(mtime)

    size = _safe_attr(item, "file_size")
    if size:
        result["file_size"] = size

    delegate = _safe_attr(item, "delegate_folder_identifier")
    if delegate:
        result["delegate_guid"] = delegate

    if name:
        result["name"] = name
    else:
        # A container that carries no name of its own -- for example the property
        # view that sits between the "Computers and Devices" root and a network
        # location. Mark it transparent so it contributes no segment to its
        # children's paths rather than injecting a placeholder into every path
        # below it.
        result["name"] = None
        result["transparent"] = True
    return result


def _join(parent: Optional[str], name: str) -> str:
    """Join a parent path and a child name with exactly one backslash"""
    if not parent:
        return name
    # A UNC name is already absolute -- do not glue it onto the parent.
    if name.startswith("\\\\"):
        return name
    return parent.rstrip("\\") + "\\" + name.lstrip("\\")


def _traverse_bagmru(
    key,
    parent_path: str,
    parent_resolved: Optional[str],
    results: list,
    bag_timestamps: dict,
    path_filter: Optional[str],
    limit: int,
    source: str,
    user_profile: Optional[str],
    depth: int = 0,
) -> None:
    """
    Recursively traverse BagMRU building both a display path and, where the
    namespace allows it, a resolved filesystem path.

    Recursion is unconditional: an item that fails to decode still has its
    children walked, since pruning on a decode failure silently deletes whole
    branches of the navigation history (network shares in particular).
    """
    if depth > 64:
        return

    for val in key.values():
        if not val.name().isdigit():
            continue

        try:
            raw = val.raw_data()
        except Exception:
            continue

        item = _decode_shell_item(raw)
        name = item.get("name")
        transparent = item.get("transparent") and not name

        # A transparent node adds no segment; its children hang off the parent.
        full_path = parent_path if transparent else _join(parent_path, name)

        # An item carrying a filesystem anchor (known folder, drive, UNC path)
        # restarts the resolved path; otherwise extend the parent's.
        anchor = item.get("fs_anchor")
        if anchor:
            resolved = anchor
            if user_profile and "%USERPROFILE%" in resolved:
                resolved = resolved.replace("%USERPROFILE%", user_profile)
        elif transparent:
            resolved = parent_resolved
        elif parent_resolved:
            resolved = _join(parent_resolved, name)
        else:
            resolved = None

        entry: dict[str, Any] = {
            "path": full_path,
            "source": source,
        }
        if resolved and resolved != full_path:
            entry["resolved_path"] = resolved
        for field in (
            "folder_type", "short_name", "modified_time", "created_time",
            "accessed_time", "file_size", "guid", "location", "description",
            "class_type", "decode_error",
        ):
            if item.get(field) is not None:
                entry[field] = item[field]

        # NodeSlot lives on the BagMRU child key; its Bags\<slot> last-write time
        # is when the folder was last interacted with in Explorer.
        subkey = None
        try:
            subkey = key.subkey(val.name())
        except Exception:
            pass

        if subkey is not None:
            try:
                node_slot = subkey.value("NodeSlot").value()
                entry["node_slot"] = node_slot
                if node_slot in bag_timestamps:
                    entry["last_viewed"] = bag_timestamps[node_slot]
            except Exception:
                pass

        # A transparent node is only worth reporting if it has its own NodeSlot
        # (and therefore its own interaction timestamp); otherwise it would just
        # duplicate its parent's path.
        emit = bool(full_path) and (not transparent or "node_slot" in entry)

        matches = (
            not path_filter
            or path_filter.lower() in full_path.lower()
            or (resolved and path_filter.lower() in resolved.lower())
        )

        if emit and matches and len(results) < limit:
            results.append(entry)

        # Recurse regardless of whether this item decoded or matched the filter.
        if subkey is not None:
            _traverse_bagmru(
                subkey, full_path, resolved, results, bag_timestamps,
                path_filter, limit, source, user_profile, depth + 1,
            )


def _get_bag_timestamps(reg, bags_root: str) -> dict[int, str]:
    """
    Map NodeSlot -> last interacted time.

    This is the last-write time of ``Bags\\<slot>`` itself. It is deliberately
    NOT the ``Bags\\<slot>\\Shell`` subkey, which Explorer rewrites when it
    persists view settings on *leaving* a folder and therefore runs late.
    """
    timestamps: dict[int, str] = {}
    try:
        bags = reg.open(bags_root)
    except Exception:
        return timestamps

    for bag_key in bags.subkeys():
        try:
            bag_num = int(bag_key.name())
        except ValueError:
            continue
        try:
            last_write = bag_key.timestamp()
            if last_write:
                timestamps[bag_num] = _format_datetime(last_write)
        except Exception:
            pass

    return timestamps


def _infer_user_profile(hive_path: Path) -> Optional[str]:
    """
    Derive the Windows user profile path from a hive's location on disk.

    Recognizes both ``.../Users/<name>/NTUSER.DAT`` and
    ``.../Users/<name>/AppData/Local/Microsoft/Windows/UsrClass.dat``.
    """
    parts = list(hive_path.resolve().parts)
    for i in range(len(parts) - 2, -1, -1):
        if parts[i].lower() == "users" and i + 1 < len(parts):
            return "C:\\Users\\" + parts[i + 1]
    return None


def _find_ntuser(usrclass_path: Path) -> Optional[Path]:
    """
    Locate the NTUSER.DAT belonging to the same profile as a UsrClass.dat.

    UsrClass.dat sits at <profile>/AppData/Local/Microsoft/Windows/UsrClass.dat,
    so the profile root is five levels up.
    """
    if usrclass_path.name.upper().startswith("NTUSER"):
        return None

    candidates = []
    profile = usrclass_path.parent
    for _ in range(5):
        profile = profile.parent
        candidates.append(profile / "NTUSER.DAT")

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _parse_one_hive(
    hive_path: Path,
    bagmru_root: str,
    bags_root: str,
    source: str,
    path_filter: Optional[str],
    include_timestamps: bool,
    limit: int,
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """Parse a single hive's BagMRU tree. Returns (entries, error)"""
    try:
        reg = Registry.Registry(str(hive_path))
    except Exception as exc:
        return [], f"failed to open {hive_path.name}: {exc}"

    bag_timestamps = {}
    if include_timestamps:
        bag_timestamps = _get_bag_timestamps(reg, bags_root)

    try:
        bagmru = reg.open(bagmru_root)
    except Exception:
        return [], f"BagMRU key not found in {hive_path.name}"

    results: list[dict[str, Any]] = []
    _traverse_bagmru(
        bagmru, "", None, results, bag_timestamps, path_filter, limit,
        source, _infer_user_profile(hive_path),
    )
    return results, None


def parse_shellbags(
    usrclass_path: str | Path,
    path_filter: Optional[str] = None,
    include_timestamps: bool = True,
    limit: int = MAX_REGISTRY_RESULTS,
    ntuser_path: Optional[str | Path] = None,
    include_ntuser: bool = True,
) -> dict[str, Any]:
    """
    Parse ShellBags to reveal folder navigation history.

    Parses the UsrClass.dat BagMRU (libraries, archive interiors, most folder
    navigation) and, unless disabled, the NTUSER.DAT BagMRU for the same profile
    (the Desktop namespace, where network share browsing is often recorded).
    Some entries -- notably files reached over a UNC path -- exist in only one of
    the two hives, so both are needed for a complete picture.

    Args:
        usrclass_path: Path to UsrClass.dat (or an NTUSER.DAT directly)
        path_filter: Filter results by path substring (case-insensitive)
        include_timestamps: Include last interacted times from the Bags key
        limit: Maximum number of results per hive
        ntuser_path: Explicit NTUSER.DAT path; auto-detected when omitted
        include_ntuser: Set False to parse only the hive given

    Returns:
        Dictionary with the merged list of visited folders
    """
    check_registry_available()
    check_fwsi_available()

    usrclass_path = Path(usrclass_path)
    if not usrclass_path.exists():
        raise FileNotFoundError(f"Registry hive not found: {usrclass_path}")

    hives: list[tuple[Path, str, str, str]] = []
    is_ntuser = usrclass_path.name.upper().startswith("NTUSER")

    if is_ntuser:
        hives.append((usrclass_path, NTUSER_BAGMRU, NTUSER_BAGS, "NTUSER.DAT"))
    else:
        hives.append((usrclass_path, USRCLASS_BAGMRU, USRCLASS_BAGS, "UsrClass.dat"))

        if include_ntuser:
            resolved_ntuser = Path(ntuser_path) if ntuser_path else _find_ntuser(usrclass_path)
            if resolved_ntuser and resolved_ntuser.exists():
                hives.append((resolved_ntuser, NTUSER_BAGMRU, NTUSER_BAGS, "NTUSER.DAT"))

    all_results: list[dict[str, Any]] = []
    hives_parsed: list[str] = []
    warnings: list[str] = []

    for hive, bagmru_root, bags_root, source in hives:
        entries, error = _parse_one_hive(
            hive, bagmru_root, bags_root, source,
            path_filter, include_timestamps, limit,
        )
        if error:
            warnings.append(error)
        else:
            hives_parsed.append(str(hive))
        all_results.extend(entries)

    if not hives_parsed and warnings:
        return {
            "usrclass_path": str(usrclass_path),
            "error": "; ".join(warnings),
            "folders": [],
        }

    # Most recently interacted first; undated entries last.
    dated = [r for r in all_results if r.get("last_viewed")]
    undated = [r for r in all_results if not r.get("last_viewed")]
    dated.sort(key=lambda x: x["last_viewed"], reverse=True)
    sorted_results = dated + undated

    result: dict[str, Any] = {
        "usrclass_path": str(usrclass_path),
        "hives_parsed": hives_parsed,
        "total_folders": len(sorted_results),
        "folders": sorted_results,
    }
    if warnings:
        result["warnings"] = warnings
    return result


def search_shellbags(
    usrclass_path: str | Path,
    search_term: str,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Search ShellBags for folders matching a search term.

    Args:
        usrclass_path: Path to UsrClass.dat registry hive
        search_term: Search term (case-insensitive substring match)
        limit: Maximum number of results

    Returns:
        Matching folders
    """
    return parse_shellbags(
        usrclass_path,
        path_filter=search_term,
        include_timestamps=True,
        limit=limit,
    )


def get_recently_viewed_folders(
    usrclass_path: str | Path,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Get recently viewed folders from ShellBags.

    Args:
        usrclass_path: Path to UsrClass.dat registry hive
        limit: Maximum number of results

    Returns:
        Recently viewed folders sorted by last access time
    """
    result = parse_shellbags(usrclass_path, include_timestamps=True, limit=limit * 2)

    folders_with_timestamps = [
        f for f in result.get("folders", [])
        if f.get("last_viewed")
    ][:limit]

    return {
        "usrclass_path": str(usrclass_path),
        "total_folders": len(folders_with_timestamps),
        "recently_viewed": folders_with_timestamps,
    }


def find_suspicious_folders(
    usrclass_path: str | Path,
    limit: int = MAX_REGISTRY_RESULTS,
) -> dict[str, Any]:
    """
    Find potentially suspicious folder access patterns.

    Looks for:
    - Temp folders
    - AppData folders
    - System folders (Windows, System32)
    - Network shares
    - Removable drives
    - Archive interiors (Explorer-browsed ZIP contents)
    - Known tool/malware paths

    Args:
        usrclass_path: Path to UsrClass.dat registry hive
        limit: Maximum number of results

    Returns:
        Suspicious folder accesses
    """
    suspicious_patterns = [
        "\\temp",
        "\\tmp",
        "appdata\\local\\temp",
        "appdata\\roaming",
        "\\system32",
        "\\syswow64",
        "\\programdata",
        "\\$recycle.bin",
        "\\tools",
        "\\hack",
        "mimikatz",
        "bloodhound",
        "sharphound",
        "rubeus",
        "cobalt",
        "empire",
        "metasploit",
        "\\public\\",
        "c:\\users\\public",
    ]

    result = parse_shellbags(usrclass_path, include_timestamps=True, limit=limit * 10)

    suspicious = []
    for folder in result.get("folders", []):
        path_lower = folder["path"].lower()
        resolved_lower = (folder.get("resolved_path") or "").lower()
        haystack = path_lower + "\n" + resolved_lower

        # Network share access
        if path_lower.startswith("\\\\") or resolved_lower.startswith("\\\\"):
            folder["reason"] = "Network share access"
            suspicious.append(folder)
            continue

        # Archive interior browsing (Temp1_*.zip style extraction folders too)
        if folder.get("folder_type") == "archive" or "temp1_" in haystack:
            folder["reason"] = "Archive contents browsed in Explorer"
            suspicious.append(folder)
            continue

        # Removable/secondary drives (anything but C:)
        drive = resolved_lower or path_lower
        if len(drive) >= 2 and drive[1] == ":" and drive[0] in "defghijklmnopqrstuvwxyz":
            folder["reason"] = "Removable/secondary drive access"
            suspicious.append(folder)
            continue

        for pattern in suspicious_patterns:
            if pattern in haystack:
                folder["reason"] = f"Suspicious path pattern: {pattern}"
                suspicious.append(folder)
                break

        if len(suspicious) >= limit:
            break

    return {
        "usrclass_path": str(usrclass_path),
        "total_suspicious": len(suspicious),
        "suspicious_folders": suspicious[:limit],
    }
