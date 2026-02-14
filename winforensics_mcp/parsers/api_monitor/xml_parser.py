"""Parse Rohitab API Monitor XML definition files into a SQLite database.

Walks the API Monitor XML directory tree (2,121 files), resolves <Include>
directives with cycle detection, and stores APIs, parameters, and type
definitions in a queryable SQLite database.
"""
from __future__ import annotations

import logging
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger("winforensics-mcp.api-monitor")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS apis (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    module TEXT NOT NULL,
    category TEXT,
    calling_convention TEXT,
    return_type TEXT,
    error_func TEXT,
    charset TEXT DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_apis_name ON apis(name);
CREATE INDEX IF NOT EXISTS idx_apis_module ON apis(module);
CREATE INDEX IF NOT EXISTS idx_apis_category ON apis(category);

CREATE TABLE IF NOT EXISTS params (
    id INTEGER PRIMARY KEY,
    api_id INTEGER REFERENCES apis(id),
    ordinal INTEGER,
    name TEXT,
    type TEXT
);

CREATE TABLE IF NOT EXISTS types (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    base_type TEXT,
    size INTEGER,
    source_file TEXT
);
CREATE INDEX IF NOT EXISTS idx_types_name ON types(name);

CREATE TABLE IF NOT EXISTS type_values (
    id INTEGER PRIMARY KEY,
    type_id INTEGER REFERENCES types(id),
    name TEXT NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS type_fields (
    id INTEGER PRIMARY KEY,
    type_id INTEGER REFERENCES types(id),
    ordinal INTEGER,
    name TEXT,
    field_type TEXT
);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _normalize_include_path(include_path: str) -> str:
    """Normalize backslash paths from XML to forward slash."""
    return include_path.replace("\\", "/")


def _resolve_include(base_dir: Path, include_path: str) -> Path | None:
    """Resolve an <Include Filename="..."> to an absolute path."""
    normalized = _normalize_include_path(include_path)
    candidate = base_dir / normalized
    if candidate.exists():
        return candidate.resolve()
    return None


def _map_variable_kind(type_attr: str) -> str:
    """Map XML Type attribute to our kind enum."""
    mapping = {
        "Alias": "alias",
        "Pointer": "pointer",
        "Integer": "integer",
        "Struct": "struct",
        "Union": "union",
        "Enum": "enum",
        "Flag": "flag",
        "Array": "array",
    }
    return mapping.get(type_attr, type_attr.lower())


class _ParserContext:
    """Holds state during XML tree walk."""

    __slots__ = (
        "db", "xml_dir", "visited", "api_count", "type_count",
        "module_set", "file_count",
    )

    def __init__(self, db: sqlite3.Connection, xml_dir: Path):
        self.db = db
        self.xml_dir = xml_dir
        self.visited: set[Path] = set()
        self.api_count = 0
        self.type_count = 0
        self.module_set: set[str] = set()
        self.file_count = 0


def _parse_variable(ctx: _ParserContext, elem: ET.Element, source_file: str) -> None:
    """Parse a <Variable> element into the types table."""
    name = elem.get("Name")
    type_attr = elem.get("Type")
    if not name or not type_attr:
        return

    kind = _map_variable_kind(type_attr)
    base_type = elem.get("Base")
    size = None
    count = elem.get("Count")
    if count:
        try:
            size = int(count)
        except ValueError:
            pass
    if type_attr == "Integer":
        size_attr = elem.get("Size")
        if size_attr:
            try:
                size = int(size_attr)
            except ValueError:
                pass

    cur = ctx.db.execute(
        "INSERT INTO types (name, kind, base_type, size, source_file) VALUES (?, ?, ?, ?, ?)",
        (name, kind, base_type, size, source_file),
    )
    type_id = cur.lastrowid
    ctx.type_count += 1

    # Enum/Flag values from child <Set> elements (inside <Enum> or <Flag>)
    for container_tag in ("Enum", "Flag"):
        container = elem.find(container_tag)
        if container is not None:
            for set_elem in container.findall("Set"):
                val_name = set_elem.get("Name", "")
                val_value = set_elem.get("Value", "")
                ctx.db.execute(
                    "INSERT INTO type_values (type_id, name, value) VALUES (?, ?, ?)",
                    (type_id, val_name, val_value),
                )

    # Struct/Union fields from child <Field> elements
    for ordinal, field in enumerate(elem.findall("Field")):
        field_name = field.get("Name")
        field_type = field.get("Type")
        ctx.db.execute(
            "INSERT INTO type_fields (type_id, ordinal, name, field_type) VALUES (?, ?, ?, ?)",
            (type_id, ordinal, field_name, field_type),
        )


def _insert_api(
    ctx: _ParserContext,
    api_elem: ET.Element,
    module_name: str,
    category: str | None,
    calling_convention: str | None,
    error_func: str | None,
    charset: str | None,
    source_file: str,
) -> None:
    """Insert a single API entry with its parameters."""
    api_name = api_elem.get("Name")
    if not api_name:
        return

    # Return type
    return_elem = api_elem.find("Return")
    return_type = return_elem.get("Type") if return_elem is not None else None

    # Per-API overrides
    api_cc = api_elem.get("CallingConvention", calling_convention)
    api_ef = api_elem.get("ErrorFunc", error_func)

    both_charset = api_elem.get("BothCharset", "").lower() == "true"

    if both_charset:
        suffix_a = api_elem.get("SuffixA", "A")
        suffix_w = api_elem.get("SuffixW", "W")
        variants = [(api_name + suffix_w, "W"), (api_name + suffix_a, "A")]
    elif charset:
        variants = [(api_name, charset)]
    else:
        variants = [(api_name, None)]

    # Collect params once
    params = []
    for ordinal, param in enumerate(api_elem.findall("Param")):
        params.append((ordinal, param.get("Name"), param.get("Type")))

    for variant_name, variant_charset in variants:
        cur = ctx.db.execute(
            "INSERT INTO apis (name, module, category, calling_convention, return_type, error_func, charset) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (variant_name, module_name, category, api_cc, return_type, api_ef, variant_charset),
        )
        api_id = cur.lastrowid
        ctx.api_count += 1

        for ordinal, pname, ptype in params:
            ctx.db.execute(
                "INSERT INTO params (api_id, ordinal, name, type) VALUES (?, ?, ?, ?)",
                (api_id, ordinal, pname, ptype),
            )


def _process_file(ctx: _ParserContext, xml_path: Path) -> None:
    """Process a single XML file, resolving includes recursively."""
    resolved = xml_path.resolve()
    if resolved in ctx.visited:
        return
    ctx.visited.add(resolved)
    ctx.file_count += 1

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        logger.warning("Failed to parse %s: %s", xml_path, e)
        return

    root = tree.getroot()
    source_file = str(xml_path.relative_to(ctx.xml_dir))

    _walk_element(ctx, root, xml_path.parent, source_file, None, None, None, None)


def _walk_element(
    ctx: _ParserContext,
    elem: ET.Element,
    current_dir: Path,
    source_file: str,
    module_name: str | None,
    category: str | None,
    calling_convention: str | None,
    error_func: str | None,
) -> None:
    """Recursively walk XML elements, tracking Module/Category context."""
    for child in elem:
        tag = child.tag

        if tag == "Include":
            inc_path = child.get("Filename")
            if inc_path:
                resolved = _resolve_include(ctx.xml_dir, inc_path)
                if resolved is None:
                    # Try relative to current file
                    resolved = _resolve_include(current_dir, inc_path)
                if resolved and resolved not in ctx.visited:
                    _process_file(ctx, resolved)

        elif tag == "Module":
            mod_name = child.get("Name", "")
            cc = child.get("CallingConvention", calling_convention)
            ef = child.get("ErrorFunc", error_func)
            ctx.module_set.add(mod_name)
            _walk_element(ctx, child, current_dir, source_file, mod_name, None, cc, ef)

        elif tag == "Interface":
            iface_name = child.get("Name", "")
            cc = child.get("CallingConvention", calling_convention)
            ef = child.get("ErrorFunc", error_func)
            iface_cat = child.get("Category", category)
            ctx.module_set.add(iface_name)
            _walk_element(ctx, child, current_dir, source_file, iface_name, iface_cat, cc, ef)

        elif tag == "Category":
            cat_name = child.get("Name", "")
            # Category applies to subsequent siblings - handled by positional state
            # We update category and continue processing children
            _walk_element(ctx, child, current_dir, source_file, module_name, cat_name, calling_convention, error_func)
            # Update category for subsequent siblings at this level
            category = cat_name

        elif tag == "Api":
            _insert_api(ctx, child, module_name or "", category, calling_convention, error_func, None, source_file)

        elif tag == "Variable":
            _parse_variable(ctx, child, source_file)

        elif tag == "Condition":
            # Architecture conditions - process children with same context
            _walk_element(ctx, child, current_dir, source_file, module_name, category, calling_convention, error_func)

        else:
            # Recurse into unknown containers (e.g., ApiMonitor root)
            _walk_element(ctx, child, current_dir, source_file, module_name, category, calling_convention, error_func)


def build_api_database(xml_dir: str | Path, db_path: str | Path) -> dict:
    """Parse all API Monitor XML definition files and build a SQLite database.

    Args:
        xml_dir: Path to the API Monitor XML definitions root directory
        db_path: Path where the SQLite database will be created

    Returns:
        Stats dict: {"apis_parsed", "types_parsed", "modules_parsed",
                      "files_parsed", "db_path"}
    """
    xml_dir = Path(xml_dir)
    db_path = Path(db_path)

    if not xml_dir.is_dir():
        raise FileNotFoundError(f"XML directory not found: {xml_dir}")

    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove existing DB for clean rebuild
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA_SQL)

    ctx = _ParserContext(conn, xml_dir)

    # Walk all XML files in the directory tree
    xml_files = sorted(xml_dir.rglob("*.xml"))
    logger.info("Found %d XML files to parse in %s", len(xml_files), xml_dir)

    for xml_file in xml_files:
        _process_file(ctx, xml_file)

    # Store metadata
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('xml_dir', ?)",
        (str(xml_dir),),
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('apis_count', ?)",
        (str(ctx.api_count),),
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('types_count', ?)",
        (str(ctx.type_count),),
    )

    conn.commit()
    conn.close()

    stats = {
        "apis_parsed": ctx.api_count,
        "types_parsed": ctx.type_count,
        "modules_parsed": len(ctx.module_set),
        "files_parsed": ctx.file_count,
        "db_path": str(db_path),
    }
    logger.info(
        "API database built: %d APIs, %d types, %d modules from %d files",
        ctx.api_count, ctx.type_count, len(ctx.module_set), ctx.file_count,
    )
    return stats
