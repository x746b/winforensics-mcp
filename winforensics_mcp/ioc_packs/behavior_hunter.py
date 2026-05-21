"""Metadata-driven behavioral IoC pack hunter."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .loader import load_ioc_pack

TEXT_EXTENSIONS = {
    ".csv", ".json", ".jsonl", ".log", ".txt", ".xml", ".yaml", ".yml",
    ".md", ".ps1", ".bat", ".cmd", ".vbs", ".evtx.txt",
}

PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def _iter_candidate_files(root: Path, max_files: int, max_file_size: int):
    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            break
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue
        count += 1
        yield path


def _is_text_candidate(path: Path) -> bool:
    suffixes = "".join(path.suffixes).lower()
    return path.suffix.lower() in TEXT_EXTENSIONS or suffixes.endswith(".evtx.txt")


def _preview(text: str, start: int, end: int, radius: int = 80) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return " ".join(text[left:right].replace("\x00", " ").split())


def _compile_regex(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)


def _decode_text_variants(raw: bytes) -> list[str]:
    variants = [raw.decode("utf-8", errors="replace")]

    # Windows text exports are commonly UTF-16LE; try it when the byte stream
    # looks like wide text or has a BOM.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in raw[:512]:
        for encoding in ("utf-16", "utf-16-le"):
            try:
                decoded = raw.decode(encoding)
            except UnicodeError:
                continue
            if decoded not in variants:
                variants.append(decoded)

    return variants


def _match_text_detector(detector: dict[str, Any], text: str) -> list[dict[str, Any]]:
    matches = []
    patterns = detector.get("patterns") or [detector.get("pattern")]
    patterns = [p for p in patterns if p]
    mode = detector.get("mode", "any")

    matched = []
    for pattern in patterns:
        regex = _compile_regex(pattern)
        match = regex.search(text)
        if match:
            matched.append((pattern, match))

    if not matched:
        return []
    if mode == "all" and len(matched) != len(patterns):
        return []

    for pattern, match in matched:
        matches.append({
            "pattern": pattern,
            "match": match.group(0)[:160],
            "preview": _preview(text, match.start(), match.end()),
        })
    return matches


def _scan_files_for_rule(
    artifacts_dir: Path,
    rule: dict[str, Any],
    max_files: int,
    max_file_size: int,
    limit: int,
) -> list[dict[str, Any]]:
    hits = []
    detectors = rule.get("detectors", [])

    for path in _iter_candidate_files(artifacts_dir, max_files, max_file_size):
        rel_path = str(path.relative_to(artifacts_dir))

        for detector in detectors:
            dtype = detector.get("type")
            if dtype == "filename_regex":
                pattern = detector.get("pattern")
                if pattern and re.search(pattern, rel_path, re.IGNORECASE):
                    hits.append({
                        "source": "filesystem_path",
                        "path": rel_path,
                        "detector": detector.get("name", dtype),
                        "match": rel_path,
                    })

            if dtype != "text_regex" or not _is_text_candidate(path):
                continue

            try:
                raw = path.read_bytes()
            except OSError:
                continue
            for text in _decode_text_variants(raw):
                for match in _match_text_detector(detector, text):
                    hits.append({
                        "source": "file_text",
                        "path": rel_path,
                        "detector": detector.get("name", dtype),
                        **match,
                    })
                    if len(hits) >= limit:
                        return hits

        if len(hits) >= limit:
            return hits

    return hits


def _scan_pcaps_for_rule(
    artifacts_dir: Path,
    rule: dict[str, Any],
    max_files: int,
    max_file_size: int,
    limit: int,
) -> list[dict[str, Any]]:
    from ..parsers.pcap_parser import SCAPY_AVAILABLE, search_pcap

    if not SCAPY_AVAILABLE:
        return []

    hits = []
    detectors = [d for d in rule.get("detectors", []) if d.get("type") == "pcap_payload_regex"]
    if not detectors:
        return hits

    pcap_files = [
        p for p in _iter_candidate_files(artifacts_dir, max_files, max_file_size)
        if p.suffix.lower() in PCAP_EXTENSIONS
    ]

    for pcap in pcap_files:
        rel_path = str(pcap.relative_to(artifacts_dir))
        for detector in detectors:
            patterns = detector.get("patterns") or [detector.get("pattern")]
            patterns = [p for p in patterns if p]
            for pattern in patterns:
                try:
                    result = search_pcap(pcap, pattern, regex=True, limit=limit)
                except Exception:
                    continue
                for match in result.get("matches", []):
                    hits.append({
                        "source": "pcap_payload",
                        "path": rel_path,
                        "detector": detector.get("name", "pcap_payload_regex"),
                        "pattern": pattern,
                        "packet_number": match.get("packet_number"),
                        "timestamp": match.get("timestamp"),
                        "src_ip": match.get("src_ip"),
                        "dst_ip": match.get("dst_ip"),
                        "src_port": match.get("src_port"),
                        "dst_port": match.get("dst_port"),
                        "preview": match.get("payload_preview"),
                    })
                    if len(hits) >= limit:
                        return hits

    return hits


def _confidence_from_score(score: int) -> str:
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def hunt_ioc_pack(
    artifacts_dir: str | Path,
    pack: str = "impacket-iocs",
    pack_path: str | None = None,
    scan_files: bool = True,
    scan_pcap: bool = True,
    max_files: int = 2000,
    max_file_size: int = 2_000_000,
    limit: int = 100,
) -> dict[str, Any]:
    """Hunt for behavioral IoCs defined in a metadata pack."""
    root = Path(artifacts_dir)
    ioc_pack = load_ioc_pack(pack=pack, pack_path=pack_path)

    if not root.exists():
        raise FileNotFoundError(f"Artifacts directory not found: {root}")

    findings = []
    total_score = 0

    for rule in ioc_pack.get("rules", []):
        rule_hits = []
        if scan_files:
            rule_hits.extend(_scan_files_for_rule(root, rule, max_files, max_file_size, limit))
        if scan_pcap:
            rule_hits.extend(_scan_pcaps_for_rule(root, rule, max_files, max_file_size, limit))

        if not rule_hits:
            continue

        score = int(rule.get("weight", 1)) * min(len(rule_hits), 3)
        total_score += score
        findings.append({
            "id": rule.get("id"),
            "name": rule.get("name"),
            "confidence": rule.get("confidence", "low"),
            "weight": rule.get("weight", 1),
            "surfaces": rule.get("surfaces", []),
            "tags": rule.get("tags", []),
            "reference": rule.get("reference"),
            "hit_count": len(rule_hits),
            "hits": rule_hits[:limit],
        })

    findings.sort(key=lambda item: (item["weight"], item["hit_count"]), reverse=True)

    return {
        "pack": {
            "id": ioc_pack.get("id"),
            "name": ioc_pack.get("name"),
            "version": ioc_pack.get("version"),
            "license": ioc_pack.get("license"),
            "upstream": ioc_pack.get("upstream"),
            "rule_count": len(ioc_pack.get("rules", [])),
        },
        "artifacts_dir": str(root),
        "found": bool(findings),
        "confidence": _confidence_from_score(total_score),
        "score": total_score,
        "matched_rules": len(findings),
        "total_hits": sum(item["hit_count"] for item in findings),
        "findings": findings[:limit],
        "summary": (
            f"Matched {len(findings)} rule(s) from {ioc_pack.get('id')} with "
            f"{sum(item['hit_count'] for item in findings)} hit(s)"
            if findings else f"No matches from {ioc_pack.get('id')}"
        ),
    }
