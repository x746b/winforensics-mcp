"""Load bundled or external IoC packs."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any


def _bundled_root():
    return files("winforensics_mcp").joinpath("ioc_packs")


def _load_pack_file(pack_file: Path) -> dict[str, Any]:
    with pack_file.open("r", encoding="utf-8") as f:
        pack = json.load(f)
    _validate_pack(pack, pack_file)
    return pack


def _validate_pack(pack: dict[str, Any], source: str | Path) -> None:
    required = {"id", "name", "version", "license", "rules"}
    missing = sorted(required - set(pack))
    if missing:
        raise ValueError(f"IoC pack {source} missing required fields: {', '.join(missing)}")
    if not isinstance(pack["rules"], list):
        raise ValueError(f"IoC pack {source} has invalid rules field")


def list_ioc_packs(extra_paths: list[str] | None = None) -> dict[str, Any]:
    """List bundled and optional external IoC packs."""
    packs = []

    for child in _bundled_root().iterdir():
        pack_file = child.joinpath("pack.json")
        if not child.is_dir() or not pack_file.is_file():
            continue
        pack = json.loads(pack_file.read_text(encoding="utf-8"))
        packs.append({
            "id": pack.get("id"),
            "name": pack.get("name"),
            "version": pack.get("version"),
            "license": pack.get("license"),
            "rule_count": len(pack.get("rules", [])),
            "source": "bundled",
            "path": str(child),
        })

    for raw_path in extra_paths or []:
        path = Path(raw_path).expanduser()
        pack_file = path / "pack.json" if path.is_dir() else path
        if not pack_file.exists():
            continue
        pack = _load_pack_file(pack_file)
        packs.append({
            "id": pack.get("id"),
            "name": pack.get("name"),
            "version": pack.get("version"),
            "license": pack.get("license"),
            "rule_count": len(pack.get("rules", [])),
            "source": "external",
            "path": str(pack_file.parent),
        })

    return {
        "pack_count": len(packs),
        "packs": sorted(packs, key=lambda item: item["id"] or ""),
    }


def load_ioc_pack(pack: str = "impacket-iocs", pack_path: str | None = None) -> dict[str, Any]:
    """Load a bundled pack by id/name, or an explicit external pack path."""
    if pack_path:
        path = Path(pack_path).expanduser()
        pack_file = path / "pack.json" if path.is_dir() else path
        return _load_pack_file(pack_file)

    root = _bundled_root()
    for child in root.iterdir():
        pack_file = child.joinpath("pack.json")
        if not child.is_dir() or not pack_file.is_file():
            continue
        data = json.loads(pack_file.read_text(encoding="utf-8"))
        if pack in {child.name, data.get("id"), data.get("name")}:
            _validate_pack(data, str(pack_file))
            return data

    raise FileNotFoundError(f"IoC pack not found: {pack}")
