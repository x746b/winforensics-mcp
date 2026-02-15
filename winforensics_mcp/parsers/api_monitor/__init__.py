"""API Monitor integration - Windows API knowledge base and pattern detection."""
from __future__ import annotations

from .xml_parser import build_api_database
from .definitions_db import lookup_api, search_api_by_category, get_api_stats, get_module_apis
from .patterns import detect_api_patterns, analyze_pe_imports_detailed
from .apmx_parser import (
    parse_apmx,
    get_apmx_calls,
    get_apmx_api_stats,
    detect_apmx_patterns,
    get_apmx_call_details,
    correlate_apmx_handles,
    get_apmx_injection_info,
    get_apmx_calls_around,
    search_apmx_params,
)

# Flag indicating the API DB module is available (always True - stdlib only)
API_DB_AVAILABLE = True

__all__ = [
    "build_api_database",
    "lookup_api",
    "search_api_by_category",
    "get_api_stats",
    "get_module_apis",
    "detect_api_patterns",
    "analyze_pe_imports_detailed",
    "parse_apmx",
    "get_apmx_calls",
    "get_apmx_api_stats",
    "detect_apmx_patterns",
    "get_apmx_call_details",
    "correlate_apmx_handles",
    "get_apmx_injection_info",
    "get_apmx_calls_around",
    "search_apmx_params",
    "API_DB_AVAILABLE",
]
