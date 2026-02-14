"""Query layer for the API Monitor SQLite knowledge base.

Provides lookup, search, and statistics functions over the pre-built
API definitions database.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def _connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a read-only connection to the API database."""
    db_path = Path(db_path)
    if not db_path.exists():
        raise FileNotFoundError(
            f"API database not found at {db_path}. "
            "Build it first with build_api_database() or the api_build_database tool."
        )
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def lookup_api(db_path: str | Path, api_name: str, include_params: bool = True) -> dict[str, Any]:
    """Look up a Windows API by name.

    Args:
        db_path: Path to api_definitions.db
        api_name: Exact name or wildcard pattern (e.g., "CreateFileW", "Create*")
        include_params: Include parameter details

    Returns:
        Dict with "results" list and "count"
    """
    conn = _connect(db_path)
    try:
        # Convert wildcard * to SQL LIKE %
        if "*" in api_name or "?" in api_name:
            pattern = api_name.replace("*", "%").replace("?", "_")
            rows = conn.execute(
                "SELECT id, name, module, category, calling_convention, return_type, "
                "error_func, charset FROM apis WHERE name LIKE ? COLLATE NOCASE ORDER BY name LIMIT 200",
                (pattern,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, name, module, category, calling_convention, return_type, "
                "error_func, charset FROM apis WHERE name = ? COLLATE NOCASE",
                (api_name,),
            ).fetchall()

        results = []
        for row in rows:
            api = {
                "name": row["name"],
                "module": row["module"],
                "category": row["category"],
                "calling_convention": row["calling_convention"],
                "return_type": row["return_type"],
                "error_func": row["error_func"],
                "charset": row["charset"],
            }
            if include_params:
                params = conn.execute(
                    "SELECT ordinal, name, type FROM params WHERE api_id = ? ORDER BY ordinal",
                    (row["id"],),
                ).fetchall()
                api["parameters"] = [
                    {"ordinal": p["ordinal"], "name": p["name"], "type": p["type"]}
                    for p in params
                ]
            results.append(api)

        return {"results": results, "count": len(results)}
    finally:
        conn.close()


def search_api_by_category(
    db_path: str | Path, category: str, limit: int = 50
) -> dict[str, Any]:
    """Search APIs by category path substring.

    Args:
        db_path: Path to api_definitions.db
        category: Category path or substring (e.g., "File Management", "Debugging")
        limit: Maximum results

    Returns:
        Dict with "results" list and "count"
    """
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT name, module, category, calling_convention, return_type "
            "FROM apis WHERE category LIKE ? COLLATE NOCASE ORDER BY category, name LIMIT ?",
            (f"%{category}%", limit),
        ).fetchall()

        results = [
            {
                "name": r["name"],
                "module": r["module"],
                "category": r["category"],
                "calling_convention": r["calling_convention"],
                "return_type": r["return_type"],
            }
            for r in rows
        ]

        # Also get distinct matching categories for navigation
        categories = conn.execute(
            "SELECT DISTINCT category, COUNT(*) as api_count FROM apis "
            "WHERE category LIKE ? COLLATE NOCASE GROUP BY category ORDER BY category LIMIT 50",
            (f"%{category}%",),
        ).fetchall()

        return {
            "results": results,
            "count": len(results),
            "matching_categories": [
                {"category": c["category"], "api_count": c["api_count"]}
                for c in categories
            ],
        }
    finally:
        conn.close()


def get_api_stats(db_path: str | Path) -> dict[str, Any]:
    """Get database statistics.

    Returns:
        Dict with total_apis, total_types, module_count, top_modules,
        top_categories
    """
    conn = _connect(db_path)
    try:
        total_apis = conn.execute("SELECT COUNT(*) FROM apis").fetchone()[0]
        total_types = conn.execute("SELECT COUNT(*) FROM types").fetchone()[0]

        modules = conn.execute(
            "SELECT module, COUNT(*) as cnt FROM apis GROUP BY module ORDER BY cnt DESC LIMIT 20"
        ).fetchall()

        categories = conn.execute(
            "SELECT category, COUNT(*) as cnt FROM apis WHERE category IS NOT NULL "
            "GROUP BY category ORDER BY cnt DESC LIMIT 20"
        ).fetchall()

        return {
            "total_apis": total_apis,
            "total_types": total_types,
            "module_count": len(
                conn.execute("SELECT DISTINCT module FROM apis").fetchall()
            ),
            "top_modules": [
                {"module": m["module"], "api_count": m["cnt"]} for m in modules
            ],
            "top_categories": [
                {"category": c["category"], "api_count": c["cnt"]} for c in categories
            ],
        }
    finally:
        conn.close()


def get_module_apis(
    db_path: str | Path, module_name: str, limit: int = 100
) -> dict[str, Any]:
    """List all APIs exported by a specific DLL/interface.

    Args:
        db_path: Path to api_definitions.db
        module_name: DLL name (e.g., "Kernel32.dll") - case-insensitive
        limit: Maximum results

    Returns:
        Dict with "module", "results" list, and "count"
    """
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT name, category, calling_convention, return_type, charset "
            "FROM apis WHERE module LIKE ? COLLATE NOCASE ORDER BY name LIMIT ?",
            (module_name, limit),
        ).fetchall()

        results = [
            {
                "name": r["name"],
                "category": r["category"],
                "calling_convention": r["calling_convention"],
                "return_type": r["return_type"],
                "charset": r["charset"],
            }
            for r in rows
        ]

        return {
            "module": module_name,
            "results": results,
            "count": len(results),
        }
    finally:
        conn.close()
