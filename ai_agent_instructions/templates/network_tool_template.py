#!/usr/bin/env python3
"""
Network Tool Template
======================

Template for building network security tools: scanners, sniffers,
protocol analyzers, MITM tools, and network exploitation utilities.

Category: A/B - Reconnaissance & Exploitation (Network)
Author: Security Research Lab
Version: 1.0.0
Date: 2026-02-08

Usage:
    Inherit from NetworkToolBase and implement the required methods.
    See the example at the bottom for a port scanner implementation.

Dependencies:
    pip install scapy

Legal:
    Authorized security testing only. See 02_LEGAL_CONTEXT.md.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import argparse
import ipaddress
import json
import logging
import socket
import sys
import time
import threading

logger = logging.getLogger("security_tool")


class TargetError(Exception):
    """Target validation / scope error."""


class ScopeGate:
    """
    Minimal scope gate for network tools.
    - Prefer explicit allowlist CIDR(s) in lab.
    - For MITM/intercept, prefer single victim+target pair (no broad scanning).
    """

    def __init__(self, allow: list[str] | None, deny: list[str] | None = None):
        self.allow = allow or []
        self.deny = deny or []

    def _match(self, ip: str, spec: str) -> bool:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return ip == spec

    def assert_in_scope(self, ip: str) -> None:
        if any(self._match(ip, d) for d in self.deny):
            raise TargetError(f"Target is denylisted: {ip}")
        if self.allow and not any(self._match(ip, a) for a in self.allow):
            raise TargetError(f"Target out of scope: {ip} (allow={self.allow})")


# ──────────────────────────────────────────────
# Network Enums & Constants
# ──────────────────────────────────────────────

class ScanType(str, Enum):
    """Network scan types."""
    TCP_CONNECT = "connect"
    TCP_SYN = "syn"
    TCP_FIN = "fin"
    TCP_XMAS = "xmas"
    TCP_NULL = "null"
    TCP_ACK = "ack"
    UDP = "udp"
    PING = "ping"


class PortState(str, Enum):
    """Port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNKNOWN = "unknown"


class Protocol(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ARP = "arp"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMB = "smb"
    RDP = "rdp"
    CUSTOM = "custom"


# Common port-service mapping
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Top 100 ports for quick scanning
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8080, 8443, 8888, 9100, 9999, 10000, 27017,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


# ──────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────

@dataclass
class HostInfo:
    """Information about a network host."""
    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    is_alive: bool = False
    ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "os_guess": self.os_guess,
            "is_alive": self.is_alive,
            "ports": [p.to_dict() for p in self.ports],
            "services": self.services,
            "metadata": self.metadata,
        }


@dataclass
class PortInfo:
    """Information about a network port."""
    port: int
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.UNKNOWN
    service: str = ""
    version: str = ""
    banner: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol.value,
            "state": self.state.value,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "metadata": self.metadata,
        }


@dataclass
class NetworkResult:
    """Result of a network operation."""
    success: bool
    hosts: list[HostInfo] = field(default_factory=list)
    data: Any = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "hosts": [h.to_dict() for h in self.hosts],
            "data": self.data,
            "error": self.error,
            "timestamp": self.timestamp,
            "duration": self.duration,
        }


# ──────────────────────────────────────────────
# Network Utility Functions
# ──────────────────────────────────────────────

def parse_targets(target_spec: str) -> list[str]:
    """
    Parse target specification into list of IP addresses.

    Supports:
        - Single IP: "192.168.1.1"
        - CIDR range: "192.168.1.0/24"
        - IP range: "192.168.1.1-254"
        - Hostname: "example.com"
        - Comma-separated: "192.168.1.1,192.168.1.2"

    Args:
        target_spec: Target specification string.

    Returns:
        List of IP address strings.
    """
    targets = []

    for spec in target_spec.split(","):
        spec = spec.strip()

        # CIDR notation
        if "/" in spec:
            try:
                network = ipaddress.ip_network(spec, strict=False)
                targets.extend(str(ip) for ip in network.hosts())
                continue
            except ValueError:
                pass

        # IP range (e.g., 192.168.1.1-254)
        if "-" in spec:
            try:
                base, end = spec.rsplit("-", 1)
                parts = base.split(".")
                start = int(parts[-1])
                end_num = int(end)
                for i in range(start, end_num + 1):
                    parts[-1] = str(i)
                    targets.append(".".join(parts))
                continue
            except (ValueError, IndexError):
                pass

        # Single IP or hostname
        try:
            ipaddress.ip_address(spec)
            targets.append(spec)
        except ValueError:
            # Try as hostname
            try:
                ip = socket.gethostbyname(spec)
                targets.append(ip)
            except socket.gaierror:
                logger.warning(f"Could not resolve: {spec}")

    return targets


def enforce_single_target_pair(victim: str, target: str) -> None:
    """
    Helper for MITM PoCs: enforce explicit victim+target single pair.
    Keeps the deliverable lab-contained and reduces accidental scope expansion.
    """
    if not victim or not target:
        raise TargetError("victim and target must be specified (single pair)")
    try:
        ipaddress.ip_address(victim)
        ipaddress.ip_address(target)
    except ValueError as e:
        raise TargetError(f"victim/target must be IP addresses: {e}")


def parse_ports(port_spec: str) -> list[int]:
    """
    Parse port specification into list of port numbers.

    Supports:
        - Single port: "80"
        - Range: "1-1024"
        - Comma-separated: "80,443,8080"
        - Mixed: "80,443,8000-8100"
        - Special: "top100", "all"

    Args:
        port_spec: Port specification string.

    Returns:
        Sorted list of port numbers.
    """
    if port_spec.lower() == "top100":
        return TOP_100_PORTS

    if port_spec.lower() == "all":
        return list(range(1, 65536))

    ports = set()
    for spec in port_spec.split(","):
        spec = spec.strip()
        if "-" in spec:
            start, end = spec.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(spec))

    return sorted(p for p in ports if 1 <= p <= 65535)


def resolve_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """
    Attempt to grab a service banner.

    Args:
        ip: Target IP address.
        port: Target port.
        timeout: Connection timeout.

    Returns:
        Banner string or empty string.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services send banner on connect
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        except socket.timeout:
            # Try sending a probe
            probes = [
                b"\r\n",                        # Generic
                b"HEAD / HTTP/1.0\r\n\r\n",    # HTTP
                b"EHLO test\r\n",               # SMTP
            ]
            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                    if banner:
                        break
                except Exception:
                    continue
            else:
                banner = ""

        sock.close()
        return banner[:500]  # Limit banner length
    except Exception:
        return ""


# ──────────────────────────────────────────────
# Network Tool Base Class
# ──────────────────────────────────────────────

class NetworkToolBase(ABC):
    """
    Abstract base class for network security tools.

    Provides:
    - Target parsing and validation
    - Multi-threaded scanning
    - Banner grabbing
    - Result formatting

    Subclasses must implement:
    - scan_host(ip, ports) — Scan a single host
    """

    NAME: str = "NetworkTool"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "Network security tool"

    def __init__(
        self,
        targets: list[str],
        ports: list[int],
        options: dict | None = None,
    ):
        """
        Initialize the network tool.

        Args:
            targets: List of target IP addresses.
            ports: List of ports to scan.
            options: Additional options.
        """
        self.targets = targets
        self.ports = ports
        self.options = options or {}
        self.results: list[HostInfo] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        # Configuration
        self.timeout = self.options.get("timeout", 3.0)
        self.threads = self.options.get("threads", 50)
        self.rate_limit = self.options.get("rate_limit", 0)  # requests/sec, 0 = unlimited
        self.banner_grab = self.options.get("banner_grab", True)
        self.resolve_dns = self.options.get("resolve_dns", True)

        # Rate limiting
        self._rate_lock = threading.Lock()
        self._last_request_time = 0.0

    def _enforce_rate_limit(self):
        """Enforce rate limiting between requests."""
        if self.rate_limit <= 0:
            return

        with self._rate_lock:
            min_interval = 1.0 / self.rate_limit
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_request_time = time.time()

    def tcp_connect_scan(self, ip: str, port: int) -> PortState:
        """
        Perform a TCP connect scan on a single port.

        Args:
            ip: Target IP address.
            port: Target port.

        Returns:
            PortState indicating the port status.
        """
        self._enforce_rate_limit()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                return PortState.OPEN
            else:
                return PortState.CLOSED
        except socket.timeout:
            return PortState.FILTERED
        except OSError:
            return PortState.FILTERED

    @abstractmethod
    def scan_host(self, ip: str, ports: list[int]) -> HostInfo:
        """
        Scan a single host. Must be implemented by subclasses.

        Args:
            ip: Target IP address.
            ports: List of ports to scan.

        Returns:
            HostInfo with scan results.
        """
        pass

    def execute(self) -> NetworkResult:
        """
        Execute the network scan across all targets.

        Returns:
            NetworkResult with all host results.
        """
        self.start_time = datetime.now()

        print(f"\n{'='*60}")
        print(f" {self.NAME} v{self.VERSION}")
        print(f" {self.DESCRIPTION}")
        print(f"{'='*60}")
        print(f" Targets: {len(self.targets)}")
        print(f" Ports:   {len(self.ports)}")
        print(f" Threads: {self.threads}")
        print(f" Started: {self.start_time.isoformat()}")
        print(f"{'='*60}\n")

        # Scan all targets using thread pool
        with ThreadPoolExecutor(max_workers=min(self.threads, len(self.targets))) as executor:
            futures = {
                executor.submit(self.scan_host, ip, self.ports): ip
                for ip in self.targets
            }

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    host_info = future.result()
                    self.results.append(host_info)

                    # Print live results
                    open_ports = [p for p in host_info.ports if p.state == PortState.OPEN]
                    if open_ports:
                        logger.info(f"{ip} - {len(open_ports)} open port(s)")
                        for p in open_ports:
                            svc = p.service or COMMON_PORTS.get(p.port, "")
                            banner_info = f" [{p.banner[:60]}]" if p.banner else ""
                            logger.info(f"  {p.port}/{p.protocol.value} {p.state.value} {svc}{banner_info}")

                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Print summary
        self._print_summary(duration)

        return NetworkResult(
            success=True,
            hosts=self.results,
            duration=duration,
        )

    def _print_summary(self, duration: float):
        """Print scan summary."""
        total_open = sum(
            len([p for p in h.ports if p.state == PortState.OPEN])
            for h in self.results
        )
        alive_hosts = sum(1 for h in self.results if h.is_alive)

        print(f"\n{'='*60}")
        print(f" Scan Complete")
        print(f"{'='*60}")
        print(f" Duration:    {duration:.2f}s")
        print(f" Hosts alive: {alive_hosts}/{len(self.targets)}")
        print(f" Open ports:  {total_open}")
        print(f"{'='*60}\n")

    def to_json(self) -> str:
        """Export results as JSON."""
        return json.dumps(
            {
                "tool": self.NAME,
                "version": self.VERSION,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "targets": self.targets,
                "ports_scanned": self.ports,
                "results": [h.to_dict() for h in self.results],
            },
            indent=2,
        )


# ──────────────────────────────────────────────
# Example: TCP Connect Scanner
# ──────────────────────────────────────────────

class TCPConnectScanner(NetworkToolBase):
    """
    Basic TCP connect scanner implementation.
    Example of how to extend NetworkToolBase.
    """

    NAME = "TCPConnectScanner"
    VERSION = "1.0.0"
    DESCRIPTION = "TCP connect port scanner"

    def scan_host(self, ip: str, ports: list[int]) -> HostInfo:
        """Scan a single host using TCP connect."""
        host = HostInfo(ip=ip)

        # Resolve hostname
        if self.resolve_dns:
            host.hostname = resolve_hostname(ip)

        # Scan ports using thread pool
        port_results = []
        with ThreadPoolExecutor(max_workers=min(self.threads, len(ports))) as executor:
            futures = {
                executor.submit(self.tcp_connect_scan, ip, port): port
                for port in ports
            }

            for future in as_completed(futures):
                port = futures[future]
                try:
                    state = future.result()
                    port_info = PortInfo(
                        port=port,
                        protocol=Protocol.TCP,
                        state=state,
                        service=COMMON_PORTS.get(port, ""),
                    )

                    # Grab banner for open ports
                    if state == PortState.OPEN and self.banner_grab:
                        port_info.banner = grab_banner(ip, port, self.timeout)

                    port_results.append(port_info)
                except Exception as e:
                    port_results.append(PortInfo(
                        port=port, state=PortState.UNKNOWN,
                        metadata={"error": str(e)}
                    ))

        host.ports = sorted(port_results, key=lambda p: p.port)
        host.is_alive = any(p.state == PortState.OPEN for p in host.ports)
        return host


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def create_network_tool_parser(
    tool_name: str, description: str
) -> argparse.ArgumentParser:
    """Create argument parser for network tools."""
    parser = argparse.ArgumentParser(
        prog=tool_name,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Targets
    parser.add_argument(
        "target",
        help="Target spec: IP, CIDR, range, hostname (e.g., 192.168.1.0/24)",
    )

    # Port options
    port_group = parser.add_argument_group("port options")
    port_group.add_argument(
        "-p", "--ports",
        default="top100",
        help="Ports to scan (e.g., '80,443', '1-1024', 'top100', 'all')",
    )

    # Scan options
    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "-sT", "--connect",
        action="store_true",
        default=True,
        help="TCP connect scan (default)",
    )
    scan_group.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Connection timeout in seconds (default: 3)",
    )
    scan_group.add_argument(
        "-T", "--threads",
        type=int,
        default=50,
        help="Number of threads (default: 50)",
    )
    scan_group.add_argument(
        "--rate-limit",
        type=float,
        default=0,
        help="Max requests/second, 0=unlimited (default: 0)",
    )
    scan_group.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing",
    )
    scan_group.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip DNS resolution",
    )

    # Output options
    out_group = parser.add_argument_group("output options")
    out_group.add_argument(
        "-o", "--output",
        help="Output file path",
    )
    out_group.add_argument(
        "-f", "--format",
        choices=["console", "json", "csv"],
        default="console",
        help="Output format (default: console)",
    )
    out_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )

    return parser


# ──────────────────────────────────────────────
# Main (Example)
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = create_network_tool_parser(
        "network_scanner",
        "TCP Connect Port Scanner - Security Research Lab",
    )
    args = parser.parse_args()

    # Parse targets and ports
    targets = parse_targets(args.target)
    ports = parse_ports(args.ports)

    if not targets:
        print("[-] No valid targets found")
        sys.exit(1)

    # Create scanner
    scanner = TCPConnectScanner(
        targets=targets,
        ports=ports,
        options={
            "timeout": args.timeout,
            "threads": args.threads,
            "rate_limit": args.rate_limit,
            "banner_grab": not args.no_banner,
            "resolve_dns": not args.no_dns,
        },
    )

    # Execute scan
    result = scanner.execute()

    # Output
    if args.output:
        output_data = scanner.to_json()
        with open(args.output, "w") as f:
            f.write(output_data)
        print(f"\n[*] Results saved to {args.output}")
