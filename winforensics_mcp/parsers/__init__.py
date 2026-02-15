from .evtx_parser import (
    get_evtx_events,
    list_evtx_files,
    get_evtx_stats,
    search_security_events,
    get_event_id_description,
    iter_evtx_events,
    EVTX_AVAILABLE,
)

from .registry_parser import (
    get_registry_key,
    search_registry_values,
    get_run_keys,
    get_services,
    get_usb_devices,
    get_user_accounts,
    get_network_interfaces,
    get_system_info,
    open_registry_hive,
    REGISTRY_AVAILABLE,
)

from .pe_analyzer import (
    analyze_pe,
    get_file_hashes,
    PEFILE_AVAILABLE,
)

from .prefetch_parser import (
    parse_prefetch_file,
    parse_prefetch_directory,
    search_prefetch_for_executable,
    get_recent_executions,
    PYSCCA_AVAILABLE,
)

from .amcache_parser import (
    parse_amcache,
    search_amcache_by_sha1,
    get_amcache_executables,
)

from .srum_parser import (
    parse_srum,
    parse_srum_app_resource_usage,
    parse_srum_network_usage,
    get_srum_summary,
    PYESEDB_AVAILABLE,
)

from .mft_parser import (
    parse_mft,
    find_timestomped_files,
    get_mft_entry,
    search_mft_by_extension,
    iter_mft_entries,
    MFT_AVAILABLE,
)

from .usn_parser import (
    parse_usn_journal,
    search_usn_for_file,
    get_file_operations_summary,
    find_deleted_files,
    iter_usn_records,
)

from .browser_parser import (
    parse_browser_history,
    search_browser_history,
    get_browser_downloads,
)

from .lnk_parser import (
    parse_lnk_file,
    parse_lnk_directory,
    get_recent_files,
    search_lnk_for_target,
    PYLNK_AVAILABLE,
)

from .shellbags_parser import (
    parse_shellbags,
    search_shellbags,
    get_recently_viewed_folders,
    find_suspicious_folders,
)

from .csv_ingestor import (
    ingest_csv,
    query_mftecmd_csv,
    query_pecmd_csv,
    query_amcache_csv,
)

from .yara_scanner import (
    scan_file as yara_scan_file,
    scan_directory as yara_scan_directory,
    scan_bytes as yara_scan_bytes,
    compile_rules as yara_compile_rules,
    list_rules as yara_list_rules,
    get_default_rules_path as yara_get_default_rules_path,
    YARA_AVAILABLE,
)

from .virustotal_client import (
    lookup_hash as vt_lookup_hash,
    lookup_ip as vt_lookup_ip,
    lookup_domain as vt_lookup_domain,
    lookup_file as vt_lookup_file,
    get_api_key as vt_get_api_key,
    clear_cache as vt_clear_cache,
    get_cache_stats as vt_get_cache_stats,
    VT_AVAILABLE,
)

from .pcap_parser import (
    get_pcap_stats,
    get_conversations as pcap_get_conversations,
    get_dns_queries as pcap_get_dns_queries,
    get_http_requests as pcap_get_http_requests,
    search_pcap,
    find_suspicious_connections as pcap_find_suspicious,
    iter_packets as pcap_iter_packets,
    SCAPY_AVAILABLE,
)

from .die_analyzer import (
    analyze_file as die_analyze_file,
    scan_directory as die_scan_directory,
    get_packer_info as die_get_packer_info,
    get_die_version,
    DIE_AVAILABLE,
)

from .api_monitor import (
    build_api_database,
    lookup_api,
    search_api_by_category,
    get_api_stats,
    get_module_apis,
    detect_api_patterns,
    analyze_pe_imports_detailed,
    parse_apmx,
    get_apmx_calls,
    get_apmx_api_stats,
    detect_apmx_patterns,
    get_apmx_call_details,
    correlate_apmx_handles,
    get_apmx_injection_info,
    get_apmx_calls_around,
    search_apmx_params,
    API_DB_AVAILABLE,
)

__all__ = [
    # EVTX
    "get_evtx_events",
    "list_evtx_files",
    "get_evtx_stats",
    "search_security_events",
    "get_event_id_description",
    "iter_evtx_events",
    "EVTX_AVAILABLE",
    # Registry
    "get_registry_key",
    "search_registry_values",
    "get_run_keys",
    "get_services",
    "get_usb_devices",
    "get_user_accounts",
    "get_network_interfaces",
    "get_system_info",
    "open_registry_hive",
    "REGISTRY_AVAILABLE",
    # PE Analysis
    "analyze_pe",
    "get_file_hashes",
    "PEFILE_AVAILABLE",
    # Prefetch
    "parse_prefetch_file",
    "parse_prefetch_directory",
    "search_prefetch_for_executable",
    "get_recent_executions",
    "PYSCCA_AVAILABLE",
    # Amcache
    "parse_amcache",
    "search_amcache_by_sha1",
    "get_amcache_executables",
    # SRUM
    "parse_srum",
    "parse_srum_app_resource_usage",
    "parse_srum_network_usage",
    "get_srum_summary",
    "PYESEDB_AVAILABLE",
    # MFT
    "parse_mft",
    "find_timestomped_files",
    "get_mft_entry",
    "search_mft_by_extension",
    "iter_mft_entries",
    "MFT_AVAILABLE",
    # USN Journal
    "parse_usn_journal",
    "search_usn_for_file",
    "get_file_operations_summary",
    "find_deleted_files",
    "iter_usn_records",
    # Browser
    "parse_browser_history",
    "search_browser_history",
    "get_browser_downloads",
    # LNK
    "parse_lnk_file",
    "parse_lnk_directory",
    "get_recent_files",
    "search_lnk_for_target",
    "PYLNK_AVAILABLE",
    # ShellBags
    "parse_shellbags",
    "search_shellbags",
    "get_recently_viewed_folders",
    "find_suspicious_folders",
    # CSV Ingestor
    "ingest_csv",
    "query_mftecmd_csv",
    "query_pecmd_csv",
    "query_amcache_csv",
    # YARA Scanner
    "yara_scan_file",
    "yara_scan_directory",
    "yara_scan_bytes",
    "yara_compile_rules",
    "yara_list_rules",
    "yara_get_default_rules_path",
    "YARA_AVAILABLE",
    # VirusTotal
    "vt_lookup_hash",
    "vt_lookup_ip",
    "vt_lookup_domain",
    "vt_lookup_file",
    "vt_get_api_key",
    "vt_clear_cache",
    "vt_get_cache_stats",
    "VT_AVAILABLE",
    # PCAP Parser
    "get_pcap_stats",
    "pcap_get_conversations",
    "pcap_get_dns_queries",
    "pcap_get_http_requests",
    "search_pcap",
    "pcap_find_suspicious",
    "pcap_iter_packets",
    "SCAPY_AVAILABLE",
    # DiE Analyzer
    "die_analyze_file",
    "die_scan_directory",
    "die_get_packer_info",
    "get_die_version",
    "DIE_AVAILABLE",
    # API Monitor
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
