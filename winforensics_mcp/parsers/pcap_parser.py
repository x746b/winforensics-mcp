"""
PCAP/PCAPNG parser for network forensics.

Features:
- Parse PCAP and PCAPNG files
- Extract conversations/flows (TCP/UDP)
- DNS query extraction
- HTTP request extraction
- Protocol statistics
- Suspicious connection detection (C2 indicators, beaconing)
- Payload search

Uses scapy for pure Python parsing without external dependencies.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional

try:
    from scapy.all import (
        DNS,
        DNSQR,
        DNSRR,
        IP,
        TCP,
        UDP,
        Raw,
        rdpcap,
        PcapNgReader,
        PcapReader,
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def check_scapy_available() -> None:
    """Raise error if scapy not available."""
    if not SCAPY_AVAILABLE:
        raise ImportError(
            "scapy library not installed. Install with: pip install scapy"
        )


def _format_timestamp(ts: float) -> str:
    """Format Unix timestamp to ISO format."""
    return datetime.utcfromtimestamp(ts).isoformat() + "Z"


def _get_packet_time(pkt) -> Optional[float]:
    """Get packet timestamp."""
    return float(pkt.time) if hasattr(pkt, "time") else None


def iter_packets(pcap_path: str | Path) -> Iterator:
    """
    Iterate over packets in a PCAP/PCAPNG file.
    Memory efficient - doesn't load entire file.
    """
    check_scapy_available()
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Try PCAPNG first, fall back to PCAP
    try:
        with PcapNgReader(str(pcap_path)) as reader:
            for pkt in reader:
                yield pkt
    except Exception:
        # Fall back to regular PCAP
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                yield pkt


def get_pcap_stats(
    pcap_path: str | Path,
    max_packets: int = 100000,
) -> dict[str, Any]:
    """
    Get statistics from a PCAP/PCAPNG file.

    Args:
        pcap_path: Path to PCAP/PCAPNG file
        max_packets: Maximum packets to analyze (for large files)

    Returns:
        {
            "file": str,
            "file_size_bytes": int,
            "packet_count": int,
            "time_range": {"start": str, "end": str, "duration_seconds": float},
            "protocols": {"TCP": int, "UDP": int, "ICMP": int, ...},
            "top_talkers": [{"ip": str, "packets": int, "bytes": int}, ...],
            "top_ports": [{"port": int, "protocol": str, "count": int}, ...],
            "dns_query_count": int,
            "http_request_count": int,
        }
    """
    check_scapy_available()
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    protocols: Counter = Counter()
    src_ips: Counter = Counter()
    dst_ips: Counter = Counter()
    ip_bytes: Counter = Counter()
    ports: Counter = Counter()

    packet_count = 0
    first_time = None
    last_time = None
    dns_count = 0
    http_count = 0
    total_bytes = 0

    for pkt in iter_packets(pcap_path):
        packet_count += 1
        if packet_count > max_packets:
            break

        # Timestamp
        pkt_time = _get_packet_time(pkt)
        if pkt_time:
            if first_time is None:
                first_time = pkt_time
            last_time = pkt_time

        # Packet size
        pkt_len = len(pkt)
        total_bytes += pkt_len

        # IP layer
        if IP in pkt:
            ip_layer = pkt[IP]
            src_ips[ip_layer.src] += 1
            dst_ips[ip_layer.dst] += 1
            ip_bytes[ip_layer.src] += pkt_len
            ip_bytes[ip_layer.dst] += pkt_len

            # Protocol
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip_layer.proto, f"Other({ip_layer.proto})")
            protocols[proto_name] += 1

            # TCP
            if TCP in pkt:
                tcp = pkt[TCP]
                ports[("TCP", tcp.sport)] += 1
                ports[("TCP", tcp.dport)] += 1

                # HTTP detection - check HTTPRequest layer first, then Raw payload
                if HTTPRequest in pkt:
                    http_count += 1
                elif tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                            http_count += 1

            # UDP
            if UDP in pkt:
                udp = pkt[UDP]
                ports[("UDP", udp.sport)] += 1
                ports[("UDP", udp.dport)] += 1

            # DNS
            if DNS in pkt:
                dns_count += 1
        else:
            protocols["Non-IP"] += 1

    # Combine src and dst for top talkers
    all_ips: Counter = Counter()
    for ip, count in src_ips.items():
        all_ips[ip] += count
    for ip, count in dst_ips.items():
        all_ips[ip] += count

    top_talkers = [
        {"ip": ip, "packets": count, "bytes": ip_bytes.get(ip, 0)}
        for ip, count in all_ips.most_common(10)
    ]

    top_ports = [
        {"port": port, "protocol": proto, "count": count}
        for (proto, port), count in ports.most_common(20)
    ]

    # Time range
    time_range = None
    if first_time and last_time:
        time_range = {
            "start": _format_timestamp(first_time),
            "end": _format_timestamp(last_time),
            "duration_seconds": round(last_time - first_time, 2),
        }

    return {
        "file": str(pcap_path),
        "file_size_bytes": pcap_path.stat().st_size,
        "packet_count": packet_count,
        "packets_analyzed": min(packet_count, max_packets),
        "truncated": packet_count > max_packets,
        "total_bytes": total_bytes,
        "time_range": time_range,
        "protocols": dict(protocols.most_common()),
        "top_talkers": top_talkers,
        "top_ports": top_ports,
        "dns_query_count": dns_count,
        "http_request_count": http_count,
    }


def get_conversations(
    pcap_path: str | Path,
    protocol: str = "all",
    limit: int = 50,
    min_packets: int = 1,
) -> dict[str, Any]:
    """
    Extract network conversations (flows) from PCAP.

    Args:
        pcap_path: Path to PCAP file
        protocol: Filter by protocol ("tcp", "udp", "all")
        limit: Maximum conversations to return
        min_packets: Minimum packets for a conversation to be included

    Returns:
        {
            "total_conversations": int,
            "conversations": [
                {
                    "src_ip": str,
                    "src_port": int,
                    "dst_ip": str,
                    "dst_port": int,
                    "protocol": str,
                    "packets": int,
                    "bytes": int,
                    "start_time": str,
                    "end_time": str,
                    "duration_seconds": float,
                }
            ]
        }
    """
    check_scapy_available()
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Conversation key: (src_ip, src_port, dst_ip, dst_port, proto)
    conversations: dict[tuple, dict] = {}

    for pkt in iter_packets(pcap_path):
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        pkt_time = _get_packet_time(pkt)
        pkt_len = len(pkt)

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in pkt:
            if protocol not in ("all", "tcp"):
                continue
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            proto = "TCP"
        elif UDP in pkt:
            if protocol not in ("all", "udp"):
                continue
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            proto = "UDP"
        else:
            continue

        # Normalize key (lower IP first for bidirectional)
        if (src_ip, src_port) > (dst_ip, dst_port):
            key = (dst_ip, dst_port, src_ip, src_port, proto)
        else:
            key = (src_ip, src_port, dst_ip, dst_port, proto)

        if key not in conversations:
            conversations[key] = {
                "src_ip": key[0],
                "src_port": key[1],
                "dst_ip": key[2],
                "dst_port": key[3],
                "protocol": proto,
                "packets": 0,
                "bytes": 0,
                "start_time": pkt_time,
                "end_time": pkt_time,
            }

        conv = conversations[key]
        conv["packets"] += 1
        conv["bytes"] += pkt_len
        if pkt_time:
            if conv["start_time"] is None or pkt_time < conv["start_time"]:
                conv["start_time"] = pkt_time
            if conv["end_time"] is None or pkt_time > conv["end_time"]:
                conv["end_time"] = pkt_time

    # Filter and sort by bytes
    filtered = [c for c in conversations.values() if c["packets"] >= min_packets]
    filtered.sort(key=lambda x: x["bytes"], reverse=True)

    # Format timestamps and calculate duration
    result = []
    for conv in filtered[:limit]:
        start = conv["start_time"]
        end = conv["end_time"]
        conv["start_time"] = _format_timestamp(start) if start else None
        conv["end_time"] = _format_timestamp(end) if end else None
        conv["duration_seconds"] = round(end - start, 2) if start and end else None
        result.append(conv)

    return {
        "total_conversations": len(filtered),
        "returned": len(result),
        "protocol_filter": protocol,
        "conversations": result,
    }


def get_dns_queries(
    pcap_path: str | Path,
    limit: int = 100,
    query_filter: Optional[str] = None,
) -> dict[str, Any]:
    """
    Extract DNS queries and responses from PCAP.

    Args:
        pcap_path: Path to PCAP file
        limit: Maximum queries to return
        query_filter: Filter by domain (substring match)

    Returns:
        {
            "total_queries": int,
            "queries": [
                {
                    "timestamp": str,
                    "src_ip": str,
                    "query_name": str,
                    "query_type": str,
                    "response_ips": [str],
                    "response_code": str,
                }
            ],
            "top_queried_domains": [{"domain": str, "count": int}],
            "unique_domains": int,
        }
    """
    check_scapy_available()
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    queries = []
    domain_counts: Counter = Counter()

    # Track query IDs to match responses
    query_map: dict[int, dict] = {}

    for pkt in iter_packets(pcap_path):
        if DNS not in pkt or IP not in pkt:
            continue

        dns = pkt[DNS]
        ip_layer = pkt[IP]
        pkt_time = _get_packet_time(pkt)

        # DNS Query
        if dns.qr == 0 and DNSQR in pkt:  # Query
            qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else str(pkt[DNSQR].qname)
            qname = qname.rstrip(".")

            # Query type mapping
            qtypes = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
                      15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
            qtype = qtypes.get(pkt[DNSQR].qtype, f"TYPE{pkt[DNSQR].qtype}")

            query_entry = {
                "timestamp": _format_timestamp(pkt_time) if pkt_time else None,
                "src_ip": ip_layer.src,
                "query_name": qname,
                "query_type": qtype,
                "response_ips": [],
                "response_code": None,
            }

            query_map[dns.id] = query_entry
            domain_counts[qname] += 1

        # DNS Response
        elif dns.qr == 1 and dns.id in query_map:  # Response
            query_entry = query_map[dns.id]

            # Response code mapping
            rcodes = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                      4: "NOTIMP", 5: "REFUSED"}
            query_entry["response_code"] = rcodes.get(dns.rcode, f"RCODE{dns.rcode}")

            # Extract answer IPs
            if dns.ancount > 0 and DNSRR in pkt:
                for i in range(dns.ancount):
                    try:
                        rr = dns.an[i]
                        if hasattr(rr, "rdata"):
                            rdata = str(rr.rdata)
                            if rr.type in (1, 28):  # A or AAAA
                                query_entry["response_ips"].append(rdata)
                    except (IndexError, AttributeError):
                        pass

    # Collect queries from map
    all_queries = list(query_map.values())

    # Apply filter
    if query_filter:
        query_filter_lower = query_filter.lower()
        all_queries = [q for q in all_queries if query_filter_lower in q["query_name"].lower()]

    # Sort by timestamp
    all_queries.sort(key=lambda x: x["timestamp"] or "")

    top_domains = [
        {"domain": domain, "count": count}
        for domain, count in domain_counts.most_common(20)
    ]

    return {
        "total_queries": len(all_queries),
        "returned": min(len(all_queries), limit),
        "filter": query_filter,
        "queries": all_queries[:limit],
        "top_queried_domains": top_domains,
        "unique_domains": len(domain_counts),
    }


def get_http_requests(
    pcap_path: str | Path,
    limit: int = 100,
    url_filter: Optional[str] = None,
    method_filter: Optional[str] = None,
) -> dict[str, Any]:
    """
    Extract HTTP requests from PCAP.

    Args:
        pcap_path: Path to PCAP file
        limit: Maximum requests to return
        url_filter: Filter by URL (substring match)
        method_filter: Filter by HTTP method (GET, POST, etc.)

    Returns:
        {
            "total_requests": int,
            "requests": [
                {
                    "timestamp": str,
                    "src_ip": str,
                    "dst_ip": str,
                    "method": str,
                    "host": str,
                    "uri": str,
                    "full_url": str,
                    "user_agent": str,
                    "content_type": str,
                }
            ],
            "top_hosts": [{"host": str, "count": int}],
            "methods": {"GET": int, "POST": int, ...},
        }
    """
    check_scapy_available()
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    requests = []
    host_counts: Counter = Counter()
    method_counts: Counter = Counter()

    for pkt in iter_packets(pcap_path):
        if IP not in pkt or TCP not in pkt:
            continue

        ip_layer = pkt[IP]
        pkt_time = _get_packet_time(pkt)

        method = None
        uri = None
        host = None
        user_agent = None
        content_type = None

        # Method 1: Check for scapy-parsed HTTPRequest layer
        if HTTPRequest in pkt:
            try:
                http_req = pkt[HTTPRequest]
                method = http_req.Method.decode() if hasattr(http_req, 'Method') and http_req.Method else None
                uri = http_req.Path.decode() if hasattr(http_req, 'Path') and http_req.Path else None
                host = http_req.Host.decode() if hasattr(http_req, 'Host') and http_req.Host else None
                user_agent = http_req.User_Agent.decode() if hasattr(http_req, 'User_Agent') and http_req.User_Agent else None
                content_type = http_req.Content_Type.decode() if hasattr(http_req, 'Content_Type') and http_req.Content_Type else None
            except Exception:
                pass

        # Method 2: Fallback to Raw payload parsing
        if method is None and Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                continue

            # Simple HTTP request detection
            http_methods = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
            if not any(payload.startswith(m) for m in http_methods):
                continue

            try:
                # Parse HTTP request
                lines = payload.split(b"\r\n")
                request_line = lines[0].decode("utf-8", errors="replace")
                parts = request_line.split(" ")

                if len(parts) >= 2:
                    method = parts[0]
                    uri = parts[1]
                else:
                    continue

                # Extract headers
                headers = {}
                for line in lines[1:]:
                    if b": " in line:
                        key, value = line.split(b": ", 1)
                        headers[key.decode("utf-8", errors="replace").lower()] = value.decode("utf-8", errors="replace")
                    elif line == b"":
                        break

                host = headers.get("host", ip_layer.dst)
                user_agent = headers.get("user-agent", "")
                content_type = headers.get("content-type", "")
            except Exception:
                continue

        # Skip if we couldn't parse HTTP
        if not method or not uri:
            continue

        # Default host to destination IP if not found
        if not host:
            host = ip_layer.dst

        # Build full URL
        full_url = f"http://{host}{uri}"

        request_entry = {
            "timestamp": _format_timestamp(pkt_time) if pkt_time else None,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "dst_port": pkt[TCP].dport,
            "method": method,
            "host": host,
            "uri": uri,
            "full_url": full_url,
            "user_agent": user_agent[:200] if user_agent else None,
            "content_type": content_type if content_type else None,
        }

        requests.append(request_entry)
        host_counts[host] += 1
        method_counts[method] += 1

    # Apply filters
    filtered = requests
    if url_filter:
        url_filter_lower = url_filter.lower()
        filtered = [r for r in filtered if url_filter_lower in r["full_url"].lower()]
    if method_filter:
        method_filter_upper = method_filter.upper()
        filtered = [r for r in filtered if r["method"] == method_filter_upper]

    # Sort by timestamp
    filtered.sort(key=lambda x: x["timestamp"] or "")

    top_hosts = [
        {"host": host, "count": count}
        for host, count in host_counts.most_common(20)
    ]

    return {
        "total_requests": len(filtered),
        "returned": min(len(filtered), limit),
        "url_filter": url_filter,
        "method_filter": method_filter,
        "requests": filtered[:limit],
        "top_hosts": top_hosts,
        "methods": dict(method_counts),
    }


def search_pcap(
    pcap_path: str | Path,
    pattern: str,
    regex: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Search for pattern in packet payloads.

    Args:
        pcap_path: Path to PCAP file
        pattern: String or regex pattern to search
        regex: If True, treat pattern as regex
        limit: Maximum matches to return

    Returns:
        {
            "pattern": str,
            "regex": bool,
            "total_matches": int,
            "matches": [
                {
                    "packet_number": int,
                    "timestamp": str,
                    "src_ip": str,
                    "dst_ip": str,
                    "protocol": str,
                    "src_port": int,
                    "dst_port": int,
                    "payload_preview": str,
                    "match_offset": int,
                }
            ]
        }
    """
    check_scapy_available()
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if regex:
        pattern_re = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
    else:
        pattern_bytes = pattern.encode() if isinstance(pattern, str) else pattern

    matches = []
    packet_num = 0

    for pkt in iter_packets(pcap_path):
        packet_num += 1

        if Raw not in pkt:
            continue

        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            continue

        # Search
        if regex:
            match = pattern_re.search(payload)
            if not match:
                continue
            match_offset = match.start()
        else:
            idx = payload.find(pattern_bytes)
            if idx == -1:
                continue
            match_offset = idx

        pkt_time = _get_packet_time(pkt)

        # Extract connection info
        src_ip = dst_ip = None
        src_port = dst_port = None
        protocol = "Unknown"

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

        # Payload preview (around match)
        start = max(0, match_offset - 20)
        end = min(len(payload), match_offset + 50)
        preview = payload[start:end].decode("utf-8", errors="replace")

        match_entry = {
            "packet_number": packet_num,
            "timestamp": _format_timestamp(pkt_time) if pkt_time else None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload_preview": preview,
            "match_offset": match_offset,
        }

        matches.append(match_entry)

        if len(matches) >= limit:
            break

    return {
        "pattern": pattern,
        "regex": regex,
        "total_matches": len(matches),
        "matches": matches,
    }


def find_suspicious_connections(
    pcap_path: str | Path,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Detect suspicious network activity indicators.

    Detects:
    - Connections to known suspicious ports (4444, 5555, etc.)
    - High-frequency beaconing patterns
    - DNS tunneling indicators (long subdomains)
    - Unusual user agents
    - Large data transfers to single hosts

    Args:
        pcap_path: Path to PCAP file
        limit: Maximum findings per category

    Returns:
        {
            "suspicious_ports": [...],
            "potential_beaconing": [...],
            "dns_tunneling_indicators": [...],
            "suspicious_user_agents": [...],
            "large_outbound_transfers": [...],
        }
    """
    check_scapy_available()
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Suspicious ports commonly used by malware/C2
    suspicious_ports = {
        4444, 5555, 6666, 7777, 8888, 9999,  # Metasploit defaults
        1234, 12345, 31337,  # Common backdoor ports
        4443, 8443, 8080, 8081, 8082,  # Alt HTTP/HTTPS
        6667, 6668, 6669,  # IRC (C2)
        1337, 1338,  # Leet ports
        3389,  # RDP (often tunneled)
        5900, 5901,  # VNC
        4545, 5454,  # Cobalt Strike defaults
    }

    # Suspicious user agents
    suspicious_ua_patterns = [
        r"python-requests",
        r"curl/",
        r"wget/",
        r"powershell",
        r"^$",  # Empty
        r"^Mozilla/4\.0$",  # Old/generic
        r"MSIE 6\.0",  # Ancient IE
    ]

    findings = {
        "suspicious_ports": [],
        "potential_beaconing": [],
        "dns_tunneling_indicators": [],
        "suspicious_user_agents": [],
        "large_outbound_transfers": [],
    }

    # Track for analysis
    connection_times: dict[tuple, list] = defaultdict(list)  # For beaconing
    outbound_bytes: dict[str, int] = defaultdict(int)  # For data exfil
    dns_queries: list[dict] = []
    http_requests: list[dict] = []

    # Track local IPs
    local_ips = set()

    for pkt in iter_packets(pcap_path):
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        pkt_time = _get_packet_time(pkt)
        pkt_len = len(pkt)

        # Track potential local IPs
        if ip_layer.src.startswith(("10.", "192.168.", "172.")):
            local_ips.add(ip_layer.src)

        # Check suspicious ports
        if TCP in pkt:
            tcp = pkt[TCP]
            for port in (tcp.sport, tcp.dport):
                if port in suspicious_ports:
                    if len(findings["suspicious_ports"]) < limit:
                        findings["suspicious_ports"].append({
                            "timestamp": _format_timestamp(pkt_time) if pkt_time else None,
                            "src_ip": ip_layer.src,
                            "dst_ip": ip_layer.dst,
                            "port": port,
                            "reason": f"Connection on suspicious port {port}",
                        })

            # Track connection times for beaconing
            conn_key = (ip_layer.src, ip_layer.dst, tcp.dport)
            if pkt_time:
                connection_times[conn_key].append(pkt_time)

            # Track outbound bytes
            if ip_layer.src in local_ips:
                outbound_bytes[ip_layer.dst] += pkt_len

            # Check HTTP user agents
            if Raw in pkt and tcp.dport in (80, 8080, 8081):
                try:
                    payload = bytes(pkt[Raw].load)
                    if payload.startswith((b"GET ", b"POST ")):
                        lines = payload.split(b"\r\n")
                        for line in lines:
                            if line.lower().startswith(b"user-agent:"):
                                ua = line[12:].decode("utf-8", errors="replace").strip()
                                for pattern in suspicious_ua_patterns:
                                    if re.search(pattern, ua, re.I):
                                        if len(findings["suspicious_user_agents"]) < limit:
                                            findings["suspicious_user_agents"].append({
                                                "timestamp": _format_timestamp(pkt_time) if pkt_time else None,
                                                "src_ip": ip_layer.src,
                                                "dst_ip": ip_layer.dst,
                                                "user_agent": ua[:100],
                                                "reason": f"Suspicious user agent pattern: {pattern}",
                                            })
                                        break
                except Exception:
                    pass

        # Check DNS for tunneling
        if DNS in pkt and DNSQR in pkt:
            try:
                qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else str(pkt[DNSQR].qname)
                qname = qname.rstrip(".")

                # DNS tunneling indicators
                # - Very long subdomain labels
                # - High entropy in subdomain
                labels = qname.split(".")
                if labels:
                    longest_label = max(len(l) for l in labels)
                    if longest_label > 40:  # Normal labels rarely exceed 20
                        if len(findings["dns_tunneling_indicators"]) < limit:
                            findings["dns_tunneling_indicators"].append({
                                "timestamp": _format_timestamp(pkt_time) if pkt_time else None,
                                "src_ip": ip_layer.src,
                                "query": qname[:100],
                                "reason": f"Unusually long DNS label ({longest_label} chars)",
                            })
            except Exception:
                pass

    # Analyze beaconing (regular intervals)
    for conn_key, times in connection_times.items():
        if len(times) < 5:
            continue

        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

        if len(intervals) >= 4:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)

            # Low variance in intervals = potential beaconing
            if avg_interval > 1 and variance < (avg_interval * 0.3) ** 2:
                if len(findings["potential_beaconing"]) < limit:
                    findings["potential_beaconing"].append({
                        "src_ip": conn_key[0],
                        "dst_ip": conn_key[1],
                        "dst_port": conn_key[2],
                        "connection_count": len(times),
                        "avg_interval_seconds": round(avg_interval, 2),
                        "reason": f"Regular connection interval (~{round(avg_interval)}s)",
                    })

    # Large outbound transfers
    for dst_ip, total_bytes in sorted(outbound_bytes.items(), key=lambda x: x[1], reverse=True):
        if total_bytes > 1_000_000:  # > 1MB
            if len(findings["large_outbound_transfers"]) < limit:
                findings["large_outbound_transfers"].append({
                    "dst_ip": dst_ip,
                    "bytes_sent": total_bytes,
                    "megabytes": round(total_bytes / 1_000_000, 2),
                    "reason": f"Large outbound transfer ({round(total_bytes/1_000_000, 2)} MB)",
                })

    # Count total findings
    total_findings = sum(len(v) for v in findings.values())

    return {
        "total_findings": total_findings,
        "findings": findings,
    }
