"""Read Windows Search EDB evidence via SIDR, with an explicitly partial ESE fallback."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import pyesedb
except ImportError:
    pyesedb = None

SIDR_VERSION = "0.9.2"
SIDR_COMMIT = "c7d3744d598ea38401c8694451c6467badbb508c"
REPO_ROOT = Path(__file__).resolve().parents[2]
REPORTS = {
    "file": "File_Report",
    "internet_history": "Internet_History_Report",
    "activity_history": "Activity_History_Report",
}
TIME_FIELDS = {
    "file": "System_DateModified",
    "internet_history": "System_Link_DateVisited",
    "activity_history": "System_ActivityHistory_StartTime",
}
MAX_DIAGNOSTICS = 20
MAX_VALUE = 2048
PAGE_BYTES = 24000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _diagnostic(result: dict, message: str) -> None:
    result["diagnostic_count"] += 1
    if len(result["diagnostics"]) < MAX_DIAGNOSTICS:
        result["diagnostics"].append(message[:512])


def _resolve_sidr(explicit: str | None) -> tuple[Path | None, list[str]]:
    candidates = (
        [explicit]
        if explicit
        else [
            os.environ.get("WINFORENSICS_SIDR_PATH"),
            str(REPO_ROOT / ".tools" / "sidr"),
            shutil.which("sidr"),
        ]
    )
    checked = []
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        checked.append(str(path))
        if path.is_file() and os.access(path, os.X_OK):
            return path, checked
    return None, checked


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (
        parsed.replace(tzinfo=timezone.utc)
        if parsed.tzinfo is None
        else parsed.astimezone(timezone.utc)
    )


def _bounded(value: Any, result: dict, depth: int = 0) -> Any:
    if isinstance(value, str):
        if len(value) > MAX_VALUE:
            result["values_truncated"] += 1
            return value[:MAX_VALUE] + "…"
        return value
    if isinstance(value, bytes):
        return _bounded(value.hex(), result)
    if isinstance(value, (list, dict)):
        if depth >= 3:
            result["values_truncated"] += 1
            return "[nested value omitted]"
        if len(value) > 64:
            result["values_truncated"] += 1
        if isinstance(value, dict):
            return {
                str(k)[:128]: _bounded(v, result, depth + 1) for k, v in list(value.items())[:64]
            }
        return [_bounded(v, result, depth + 1) for v in value[:64]]
    return value


def _sidr_rows(binary: Path, copied: Path, output: Path, timeout: int, result: dict):
    result["backend"] = "sidr"
    result["backend_metadata"] = {
        "path": str(binary),
        "sha256": _sha256(binary),
        "expected_version": SIDR_VERSION,
        "pinned_build_commit": SIDR_COMMIT,
    }
    # Redirect to files so a noisy/crashing sidecar cannot exhaust Python memory.
    with (output / "version.log").open("w+b") as version_log:
        version = subprocess.run(
            [str(binary), "--version"],
            stdout=version_log,
            stderr=subprocess.STDOUT,
            timeout=min(timeout, 10),
            check=False,
            cwd=output,
        )
        version_log.seek(0)
        version_text = version_log.read(1024).decode("utf-8", errors="replace").strip()
    result["backend_metadata"]["version"] = version_text
    if version.returncode or not re.search(r"\b0\.9\.2\b", version_text):
        raise ValueError(f"SIDR {SIDR_VERSION} is required; observed {version_text!r}")
    with (output / "sidr.log").open("w+b") as log:
        process = subprocess.run(
            [str(binary), "-f", "json", "-r", "to-file", "-o", str(output), str(copied.parent)],
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            cwd=output,
        )
        log.seek(0)
        for raw_line in log:
            line = raw_line.decode("utf-8", errors="replace").strip()
            lower = line.lower()
            if "not clean" in lower or "dirty database" in lower:
                result["database_state"] = "dirty"
            if any(marker in lower for marker in ("error", "failed", "panicked", "warning:")):
                _diagnostic(result, line)
                result["complete"] = False
        if process.returncode:
            raise ValueError(f"SIDR exited with status {process.returncode}; see diagnostics")
    reports = {}
    for kind, suffix in REPORTS.items():
        paths = sorted(output.glob(f"*_{suffix}_*.json"))
        if len(paths) != 1:
            result["complete"] = False
            _diagnostic(result, f"Expected one {suffix} JSONL report; found {len(paths)}")
        reports[kind] = paths
        if any("_dirty" in p.stem for p in paths):
            result["database_state"] = "dirty"
    if result["database_state"] == "dirty":
        result["complete"] = False
        _diagnostic(result, "Dirty ESE database: results may be inaccurate or incomplete.")
    result["reports"] = {k: [p.name for p in paths] for k, paths in reports.items()}
    if not any(reports.values()):
        raise ValueError("SIDR produced no reports; exit status alone does not prove success")
    if result["database_state"] == "unknown":
        result["database_state"] = "no_dirty_warning"
    for kind, paths in reports.items():
        for path in paths:
            with path.open(encoding="utf-8") as stream:
                for number, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                        if not isinstance(row, dict):
                            raise ValueError("JSONL row is not an object")
                    except (ValueError, UnicodeError) as exc:
                        result["complete"] = False
                        _diagnostic(result, f"{path.name}:{number}: {exc}")
                        continue
                    yield kind, row


def _fallback_rows(copied: Path, result: dict):
    result["backend"] = "pyesedb"
    result["complete"] = False
    result["content_filter_complete"] = False
    _diagnostic(
        result,
        "Partial PropertyStore fallback: long values and compressed Search "
        "content are unsupported. Zero matches are not conclusive. Install SIDR.",
    )
    database = pyesedb.file()
    try:
        database.open(str(copied))
        found = False
        for ti in range(database.get_number_of_tables()):
            table = database.get_table(ti)
            if "propertystore" not in table.get_name().lower():
                continue
            found = True
            columns = [
                (table.get_column(i).get_name(), table.get_column(i).get_type())
                for i in range(table.get_number_of_columns())
            ]
            for ri in range(table.get_number_of_records()):
                record = table.get_record(ri)
                row = {}
                for ci, (name, column_type) in enumerate(columns):
                    name = re.sub(r"^[0-9A-Fa-f]+-", "", name)
                    try:
                        if record.is_long_value(ci):
                            result["unsupported_long_values"] += 1
                            continue
                        if record.is_multi_value(ci):
                            _diagnostic(result, f"Unsupported multivalue field {name}")
                            continue
                        # AutoSummary may be compressed even when the ESE column says text.
                        if name == "System_Search_AutoSummary":
                            continue
                        if column_type in (10, 12):
                            value = record.get_value_data_as_string(ci)
                        elif column_type in (2, 3, 4, 5, 14, 15, 17):
                            value = record.get_value_data_as_integer(ci)
                        else:
                            value = record.get_value_data(ci)
                            if value is not None:
                                value = {"raw_hex": value.hex(), "ese_type": column_type}
                        if value is not None:
                            row[
                                "WorkId"
                                if name.lower() in ("documentid", "docid", "workid")
                                else name
                            ] = value
                    except (OSError, ValueError, RuntimeError) as exc:
                        _diagnostic(result, f"PropertyStore record {ri}, {name}: {exc}")
                item_type = str(row.get("System_ItemType", "")).lower()
                kind = "internet_history" if item_type == ".url" else "file"
                if any(key.startswith("System_Activity") for key in row):
                    kind = "activity_history"
                yield kind, row
        if not found:
            raise ValueError("No readable PropertyStore table; install SIDR for this database")
    finally:
        database.close()


def parse_windows_search(
    edb_path: str,
    *,
    sidr_path: str | None = None,
    report_type: str = "all",
    query: str | None = None,
    path_filter: str | None = None,
    filename_filter: str | None = None,
    content_filter: str | None = None,
    work_id: int | None = None,
    time_start: str | None = None,
    time_end: str | None = None,
    offset: int = 0,
    limit: int = 50,
    fields: list[str] | None = None,
    timeout: int = 120,
) -> dict:
    """Substring filters are case-insensitive and combined with AND.

    Time filters are inclusive UTC on the report's canonical time field (listed in
    metadata); absent/invalid timestamps cannot match. SIDR timestamps without an
    offset are UTC. ``complete`` covers extraction, not Windows indexing coverage.
    """
    result = {
        "source": str(edb_path),
        "backend": None,
        "complete": True,
        "content_filter_complete": True,
        "database_state": "unknown",
        "records": [],
        "total_records": 0,
        "matched_records": 0,
        "returned_records": 0,
        "report_counts": {kind: {"total": 0, "matched": 0} for kind in REPORTS},
        "offset": offset,
        "limit": limit,
        "next_offset": None,
        "has_more": False,
        "unsupported_long_values": 0,
        "values_truncated": 0,
        "diagnostic_count": 0,
        "diagnostics": [],
        "time_fields": TIME_FIELDS,
        "completeness_scope": "Parser extraction only; Windows Search may not index all files.",
    }
    source = Path(edb_path).expanduser()
    try:
        if report_type not in (*REPORTS, "all"):
            raise ValueError("report_type must be file, internet_history, activity_history, or all")
        for name, value, minimum, maximum in (
            ("offset", offset, 0, 2**63 - 1),
            ("limit", limit, 1, 1000),
            ("timeout", timeout, 1, 3600),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
        if fields is not None and (
            not isinstance(fields, list)
            or len(fields) > 64
            or not all(isinstance(f, str) for f in fields)
        ):
            raise ValueError("fields must be a list of at most 64 field names")
        if work_id is not None and (isinstance(work_id, bool) or not isinstance(work_id, int)):
            raise ValueError("work_id must be an integer")
        for value in (query, path_filter, filename_filter, content_filter):
            if value is not None and not isinstance(value, str):
                raise ValueError("Text filters must be strings")
        start, end = (
            _time(time_start) if time_start else None,
            _time(time_end) if time_end else None,
        )
        if start and end and start > end:
            raise ValueError("time_start must not be after time_end")
        if not source.is_file():
            raise ValueError(f"EDB file not found: {source}")
        binary, checked = _resolve_sidr(sidr_path)
        result["checked_sidr_locations"] = checked
        if binary is None and (sidr_path or pyesedb is None):
            raise ValueError(
                "SIDR executable unavailable. Checked: "
                + ", ".join(checked)
                + "; PATH: sidr. Build pinned SIDR with scripts/build_sidr.sh "
                "or set WINFORENSICS_SIDR_PATH. No backend was run."
            )
        before = _sha256(source)
        result["evidence_sha256_before"] = before
        try:
            with tempfile.TemporaryDirectory(prefix="winforensics-search-") as temp:
                root = Path(temp)
                input_dir, output = root / "input", root / "output"
                input_dir.mkdir()
                output.mkdir()
                copied = input_dir / "Windows.edb"
                shutil.copyfile(source, copied)
                if _sha256(copied) != before:
                    raise ValueError("Evidence changed while copying; retry from a stable copy")
                rows = (
                    _sidr_rows(binary, copied, output, timeout, result)
                    if binary
                    else _fallback_rows(copied, result)
                )
                page_bytes = 0
                page_full = False
                for kind, raw in rows:
                    result["total_records"] += 1
                    result["report_counts"][kind]["total"] += 1
                    if report_type != "all" and kind != report_type:
                        continue
                    path = str(raw.get("System_ItemPathDisplay") or raw.get("System_ItemUrl") or "")
                    filename = str(
                        raw.get("System_ItemName")
                        or raw.get("System_ItemNameDisplay")
                        or path.replace("\\", "/").rsplit("/", 1)[-1]
                    )
                    if any(
                        needle is not None and needle.casefold() not in haystack.casefold()
                        for needle, haystack in (
                            (query, json.dumps(raw, ensure_ascii=False)),
                            (path_filter, path),
                            (filename_filter, filename),
                            (content_filter, str(raw.get("System_Search_AutoSummary") or "")),
                        )
                    ):
                        continue
                    if work_id is not None and str(raw.get("WorkId")) != str(work_id):
                        continue
                    if start or end:
                        try:
                            timestamp = _time(str(raw.get(TIME_FIELDS[kind], "")))
                        except ValueError:
                            result["time_filter_unreadable"] = (
                                result.get("time_filter_unreadable", 0) + 1
                            )
                            continue
                        if (start and timestamp < start) or (end and timestamp > end):
                            continue
                    result["matched_records"] += 1
                    result["report_counts"][kind]["matched"] += 1
                    if result["matched_records"] <= offset or page_full:
                        continue
                    row = dict(raw, report_type=kind)
                    if fields is not None:
                        row = {key: row[key] for key in fields if key in row}
                    row = _bounded(row, result)
                    size = len(json.dumps(row, ensure_ascii=True))
                    # Ensure one bounded row always fits so pagination cannot stall.
                    if size > PAGE_BYTES:
                        row = {
                            "report_type": kind,
                            "WorkId": raw.get("WorkId"),
                            "_truncated": "Record exceeds page budget; request fewer fields",
                        }
                        result["values_truncated"] += 1
                        size = len(json.dumps(row))
                    if len(result["records"]) >= limit or page_bytes + size > PAGE_BYTES:
                        page_full = True
                        continue
                    result["records"].append(row)
                    page_bytes += size
        finally:
            after = _sha256(source)
            result["evidence_sha256_after"] = after
            result["evidence_unchanged"] = after == before
            if after != before:
                result["complete"] = False
                _diagnostic(result, "Evidence hash changed during parsing; results are unreliable")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        result["error"] = str(exc)[:1024]
        result["complete"] = False
        _diagnostic(result, str(exc))
    result["content_filter_complete"] = result["content_filter_complete"] and result["complete"]
    result["returned_records"] = len(result["records"])
    result["has_more"] = result["matched_records"] > offset + result["returned_records"]
    if result["has_more"]:
        result["next_offset"] = offset + result["returned_records"]
    return result
