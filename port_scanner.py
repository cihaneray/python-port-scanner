#!/usr/bin/python3

import ipaddress
import json
import os
import random
import socket
import sys
import threading
import time
import re

from dataclasses import dataclass
from argparse import ArgumentParser, Namespace
from queue import Queue, Empty
from typing import List, Dict, Tuple, Optional
from modules.service_prober import ServiceProber

# For SYN and UDP scanning
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, sr1, conf

    SCAPY_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ScanResult:
    scan_type: str
    scan_date: str
    hosts_scanned: int
    ports_scanned: int
    total_open: int
    targets: dict

    def __repr__(self):
        return str({'scan_info':
                        {'scan_type': self.scan_type, 'scan_date': self.scan_date, 'hosts_scanned': self.hosts_scanned,
                         'ports_scanned': self.ports_scanned, 'total_open': self.total_open}, 'targets': self.targets})


class PortScanner:
    def __init__(self) -> None:
        self.queue: Queue = Queue()
        self.open_tcp_ports: Dict[str, List[int]] = {}
        self.open_udp_ports: Dict[str, List[int]] = {}  # Track UDP ports separately
        self.lock = threading.Lock()
        self.cache_lock = threading.Lock()
        self.total_ports = 0
        self.scanned_ports = 0
        self.start_time = 0
        self.service_info_cache: Dict[str, str] = {}  # Cache for service info to avoid redundant probes

        # Rate limiting
        self.rate_limit = 0  # Packets per second (0 = no limit)
        self.last_scan_time = 0
        self.rate_limit_lock = threading.Lock()

        self.args = self._parse_arguments()

        # Set up rate limiting if needed
        if hasattr(self.args, 'rate') and self.args.rate > 0:
            self.rate_limit = self.args.rate

        # Validate arguments
        if self.args.threads < 1:
            print("Error: Thread count must be at least 1")
            sys.exit(1)

        if self.args.timeout <= 0:
            print("Error: Timeout must be greater than 0")
            sys.exit(1)

        # Check if SYN scan is available
        if self.args.syn:
            self._is_scan_available('SYN')

        # Check if UDP scan is available
        if self.args.udp:
            self._is_scan_available('UDP')

        if self.args.os_detection:
            self._is_scan_available('OS detection')

            # Store OS fingerprinting results
            self.os_results = {}

        # Load common ports from config file
        self.common_ports = self._load_port_config()

        # Banner
        self._print_banner()

        self._scan()

    def _print_banner(self) -> None:
        if self.args.quiet: return
        banner = """
        
░▒▓███████▓▒░░▒▓██████████████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
                                                             
"""
        print(banner)

    @staticmethod
    def _parse_arguments() -> Namespace:
        parser = ArgumentParser(description='Advanced Port Scanner with IPv6 Support')
        parser.add_argument('hosts', help='Host(s) to scan (can be hostname, IPv4, IPv6, or CIDR notation)')
        parser.add_argument('ports',
                            help='Port range to scan: start-end, comma-separated list (e.g. "80,443"), or "-" for all ports')
        parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads to use (default: 50)')
        parser.add_argument('-T', '--timeout', type=float, default=0.5, help='Timeout in seconds (default: 0.5)')
        parser.add_argument('-o', '--output', help='Output file for results')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all output except results')
        parser.add_argument('-b', '--banner', action='store_true', help='Attempt to grab banners from open ports')
        parser.add_argument('-s', '--syn', action='store_true', help='Use SYN scanning (requires root/admin)')
        parser.add_argument('-u', '--udp', action='store_true', help='Perform UDP scanning (requires root/admin)')
        parser.add_argument('-V', '--version-detection', action='store_true', help='Perform service version detection')
        parser.add_argument('--json', action='store_true', help='Output results in JSON format')
        parser.add_argument('--config', help='Path to custom port configuration file')
        parser.add_argument('--udp-retry', type=int, default=3, help='Number of retries for UDP scanning (default: 3)')
        parser.add_argument('--version-intensity', type=int, choices=range(0, 10), default=5,
                            help='Service version detection intensity (0-9, higher is more aggressive)')
        parser.add_argument('--rate', type=int, default=0,
                            help='Rate limit: maximum packets per second (0 = no limit)')
        parser.add_argument('--os-detection', action='store_true', help='Perform OS detection (requires root/admin)')
        parser.add_argument('--os-detection-timeout', type=float, default=1.0,
                            help='Timeout for OS detection probes in seconds (default: 1.0)')
        parser.add_argument('--ipv6', action='store_true', help='Force IPv6 scanning when possible')

        return parser.parse_args()

    @staticmethod
    def _is_root() -> bool:
        if os.name != 'nt':  # Not windows
            return os.geteuid() == 0

        try:  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _is_scan_available(self, scan_type: str) -> None:
        if not self._is_root():
            print(
                f"Error: {scan_type + ' scanning' if scan_type in ['SYN', 'UDP'] else scan_type} requires root/administrator privileges")
            sys.exit(1)
        if not SCAPY_AVAILABLE:
            print(
                f"Error: {scan_type + ' scanning' if scan_type in ['SYN', 'UDP'] else scan_type} requires the 'scapy' library")
            print("Please install it using: pip install scapy")
            sys.exit(1)

    def _load_port_config(self) -> Dict[int, str]:
        config_path = self.args.config if self.args.config else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                             'port_config.json')
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f: config = json.load(f)
                return {int(k): v for k, v in config['common_ports'].items()}
            return self._get_default_ports()
        except (json.JSONDecodeError, KeyError, IOError) as e:
            print(f"Warning: Could not load port configuration: {e}")
            return self._get_default_ports()

    @staticmethod
    def _get_default_ports() -> Dict[int, str]:
        return {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
            110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB", 1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            27017: "MongoDB",
            # Common UDP ports
            67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP",
            162: "SNMP-TRAP", 500: "IKE", 514: "Syslog", 520: "RIP", 1194: "OpenVPN", 1900: "SSDP", 5353: "mDNS",
            27015: "Steam", 44818: "EtherNet/IP"
        }

    def _create_default_config(self, config_path: str) -> None:
        default_config = {"common_ports": {str(k): v for k, v in self._get_default_ports().items()}}

        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            print(f"Created default configuration file at {config_path}")
        except IOError as e:
            print(f"Warning: Could not create default configuration file: {e}")

    @staticmethod
    def _parse_cidr(cidr: str) -> List[str]:
        try:
            if ':' in cidr:  # IPv6
                return [str(ip) for ip in ipaddress.IPv6Network(cidr, strict=False)]
            return [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
        except ValueError:
            return [cidr]

    def _resolve_targets(self, host_input: str) -> List[Tuple[str, bool]]:
        # Check if input is CIDR notation
        if '/' in host_input:
            ips = self._parse_cidr(host_input)
            return [(ip, ':' in ip) for ip in ips]

        # Otherwise, treat as single hostname/IP
        if self._is_ip(host_input):
            return [(host_input, ':' in host_input)]
        try:
            # Try to resolve hostname to both IPv4 and IPv6
            ip_list = []

            # Try IPv4 resolution
            try:
                ipv4 = socket.getaddrinfo(host_input, None, socket.AF_INET)[0][4][0]
                ip_list.append((ipv4, False))
            except socket.gaierror:
                pass

            # Try IPv6 resolution
            try:
                ipv6 = socket.getaddrinfo(host_input, None, socket.AF_INET6)[0][4][0]
                ip_list.append((ipv6, True))
            except socket.gaierror:
                pass

            # If we have both and not specifically requesting IPv6, prefer IPv4
            if len(ip_list) == 2 and not self.args.ipv6:
                return [ip_list[0]]  # Return only IPv4

            # If no addresses found, raise an error
            if not ip_list:
                raise socket.gaierror(f"Could not resolve hostname {host_input}")

            return ip_list
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {host_input}")
            sys.exit(1)

    @staticmethod
    def _is_ip(s: str) -> bool:
        """Check if string is a valid IP address (IPv4 or IPv6)."""
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _collect_service_banners(self, target: str) -> Dict[str, Dict[int, str]]:
        """Collect service banners for OS fingerprinting."""
        banners = {"tcp": {}, "udp": {}}

        # Collect TCP banners
        for port in self.open_tcp_ports.get(target, []):
            cached_banner = self.service_info_cache.get(f"{target}:{port}:tcp", "")
            if cached_banner:
                banners["tcp"][port] = cached_banner

        # Collect UDP banners if available
        for port in self.open_udp_ports.get(target, []):
            cached_banner = self.service_info_cache.get(f"{target}:{port}:udp", "")
            if cached_banner:
                banners["udp"][port] = cached_banner

        return banners

    def _perform_os_detection(self, target: str, is_ipv6: bool) -> dict:
        """Perform OS detection on the target."""

        from modules.os_fingerprinter import OSFingerprinter

        open_ports = self.open_tcp_ports.get(target, [])
        service_banners = self._collect_service_banners(target)
        fingerprinter = OSFingerprinter(timeout=self.args.os_detection_timeout)

        return fingerprinter.fingerprint_os(target, open_ports, service_banners, is_ipv6)

    def _parse_port_range(self) -> tuple:
        if self.args.ports == '-':
            start_port, end_port = 1, 65535
            port_list = range(1, 65536)
            return start_port, end_port, port_list

        try:
            if '-' in self.args.ports:
                start_port, end_port = map(int, self.args.ports.split('-'))
                port_list = range(start_port, end_port + 1)
            elif ',' in self.args.ports:
                # Handle comma-separated port list
                port_list = [int(p) for p in self.args.ports.split(',')]
                start_port, end_port = min(port_list), max(port_list)
            else:
                start_port = end_port = int(self.args.ports)
                port_list = [start_port]

            if not all(1 <= p <= 65535 for p in [start_port, end_port]):
                print("Error: Port numbers must be between 1 and 65535")
                sys.exit(1)

            return start_port, end_port, port_list
        except ValueError:
            print("Error: Invalid port format. Use start-end, comma-separated list, or a single port number.")
            sys.exit(1)

    def _scan(self) -> None:
        start_port, end_port, port_list = self._parse_port_range()

        target_tuples = self._resolve_targets(self.args.hosts)
        targets = [ip for ip, _ in target_tuples]

        if not targets:
            print("Error: No valid targets to scan")
            sys.exit(1)

        self.total_ports = len(port_list) * len(targets)
        if self.args.udp:
            self.total_ports *= 2  # Double for UDP scan
        self.scanned_ports = 0
        self.start_time = time.time()

        # Initialize open ports dictionary for each target
        for target in targets:
            self.open_tcp_ports[target] = []
            if self.args.udp:
                self.open_udp_ports[target] = []

        # Print scan information
        if not self.args.quiet:
            scan_types = []
            if not self.args.udp or self.args.syn:  # Default is TCP unless only UDP is specified
                scan_types.append("SYN" if self.args.syn else "TCP")
            if self.args.udp:
                scan_types.append("UDP")

            scan_type_str = " and ".join(scan_types)
            print(f"\nStarting {scan_type_str} port scan on {len(targets)} host(s)")
            if len(targets) <= 5:  # Only show all targets if 5 or fewer
                for target in targets:
                    print(f" - {target}")
            else:
                print(f" - {targets[0]}")
                print(f" - {targets[1]}")
                print(f" - ... and {len(targets) - 2} more")

            if isinstance(port_list, range) and len(port_list) > 10:
                print(f"Port range: {start_port}-{end_port}")
            else:
                print(f"Ports: {', '.join(map(str, list(port_list)[:10]))}{' ...' if len(port_list) > 10 else ''}")

            print(f"Number of threads: {self.args.threads}")
            print(f"Timeout: {self.args.timeout} seconds")
            if self.rate_limit > 0:
                print(f"Rate limit: {self.rate_limit} packets/second")
            print()

        # Fill the queue with (target, port, protocol, is_ipv6) tuples to scan
        for target, is_ipv6 in target_tuples:
            for port in port_list:
                # Add TCP scan task unless UDP-only scan is specified
                if not self.args.udp or self.args.syn:
                    self.queue.put((target, port, 'tcp', is_ipv6))

                # Add UDP scan task if UDP scanning is enabled
                if self.args.udp:
                    self.queue.put((target, port, 'udp', is_ipv6))

        # Start worker threads
        threads = []
        for _ in range(min(self.args.threads, self.total_ports)):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            threads.append(t)
            t.start()

        if not self.args.quiet:
            self._print_progress()

        # Wait for all ports to be scanned
        self.queue.join()

        if self.args.os_detection:
            print("Performing OS detection...")
            for target, is_ipv6 in target_tuples:
                sys.stdout.write(f"\r  OS detection for {target}...")
                sys.stdout.flush()

                # Only perform OS detection on hosts with open ports
                if target in self.open_tcp_ports and self.open_tcp_ports[target]:
                    os_result = self._perform_os_detection(target, is_ipv6)
                    self.os_results[target] = os_result
                    sys.stdout.write(f"\r  OS detection for {target}: {os_result['os']} "
                                     f"(Confidence: {os_result['confidence']}%)\n")
                else:
                    sys.stdout.write(f"\r  OS detection for {target}: Skipped (no open ports)\n")

        # Display results
        self._print_results(targets)

        # Save results if requested
        if self.args.output:
            if self.args.json:
                self._save_json_results(targets)
            else:
                self._save_results(targets)
        self.last_scan_time = time.time()

    def _apply_rate_limit(self):
        """Apply rate limiting if enabled."""
        if self.rate_limit <= 0:
            return

        with self.rate_limit_lock:
            current_time = time.time()
            elapsed = current_time - self.last_scan_time

            # Calculate minimum delay between packets
            min_delay = 1.0 / self.rate_limit

            # If we need to wait to maintain the rate limit
            if elapsed < min_delay:
                sleep_time = min_delay - elapsed
                time.sleep(sleep_time)

            self.last_scan_time = time.time()

    def _tcp_connect_scan(self, target_ip: str, port: int, is_ipv6: bool) -> bool:
        addr_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET

        with socket.socket(addr_family, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.args.timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                with self.lock:
                    self.open_tcp_ports[target_ip].append(port)
                return True
        return False

    def _syn_scan(self, target_ip: str, port: int, is_ipv6: bool) -> bool:
        # Disable scapy warnings
        conf.verb = 0
        # Randomize the source port for stealth scanning
        src_port = random.randint(1025, 65534)
        # Choose IPv4 or IPv6 based on target type
        packet = (IPv6(dst=target_ip) if is_ipv6 else IP(dst=target_ip)) / TCP(sport=src_port, dport=port, flags="S")
        # Set timeout and send packet
        response = sr1(packet, timeout=self.args.timeout, verbose=0)
        # Check response
        if not (response and response.haslayer(TCP)):
            return False
        tcp_layer = response.getlayer(TCP)

        # Check if SYN-ACK (flags=0x12) was received
        if tcp_layer.flags != 0x12:  # SYN-ACK
            return False
        # Send RST to close connection
        rst = (IPv6(dst=target_ip) if is_ipv6 else IP(dst=target_ip)) / TCP(sport=src_port, dport=port, flags="R")

        sr1(rst, timeout=1, verbose=0)

        with self.lock:
            self.open_tcp_ports[target_ip].append(port)
        return True

    def _udp_scan(self, target_ip: str, port: int, is_ipv6: bool) -> bool:
        """ Perform UDP port scanning with retries (supports both IPv4 and IPv6).

        - Returns True if the port is open or unresponsive (open|filtered).
        - Returns False if ICMP unreachable indicates the port is closed.
        """

        # Disable scapy warnings
        conf.verb = 0

        # Use multiple retries for UDP scan since packets can be dropped
        for _ in range(self.args.udp_retry):
            # Send UDP packet with empty payload
            src_port = random.randint(1025, 65534)

            if is_ipv6:
                packet = IPv6(dst=target_ip) / UDP(sport=src_port, dport=port)
            else:
                packet = IP(dst=target_ip) / UDP(sport=src_port, dport=port)

            # Send the packet and wait for response
            response = sr1(packet, timeout=self.args.timeout, verbose=0)

            # Process the response
            if response is None:
                # No response could mean open or filtered port
                # Continue to next retry
                continue

            # Check for ICMP unreachable errors
            if is_ipv6:
                # For IPv6, check for ICMPv6 unreachable messages (Type 1)
                if response.haslayer(ICMPv6EchoRequest) and response.type == 1:
                    return False
            else:
                # For IPv4, check for ICMP unreachable messages (Type 3)
                if response.haslayer(ICMP):
                    icmp = response.getlayer(ICMP)
                    if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                        # Port is closed or filtered
                        return False

            # If we got a UDP response, the port is definitely open
            if response.haslayer(UDP):
                with self.lock:
                    self.open_udp_ports[target_ip].append(port)
                return True

        # If we've reached here without a definitive answer, we'll consider it potentially open
        with self.lock:
            self.open_udp_ports[target_ip].append(port)
        return True

    def _grab_banner(self, ip: str, port: int, protocol: str = 'tcp', is_ipv6: bool = False) -> str:
        """Attempt to grab service banner from open port with enhanced detection."""
        if not self.args.banner and not self.args.version_detection:
            return ""

        # Check cache first to avoid redundant probes
        cache_key = f"{ip}:{port}:{protocol}"
        with self.cache_lock:
            if cache_key in self.service_info_cache:
                return self.service_info_cache[cache_key]

        # Standardize timeout handling
        effective_timeout = max(2.0, self.args.timeout)

        if protocol == 'udp':  # Basic handling for UDP
            if self.args.version_detection:
                prober = ServiceProber(timeout=effective_timeout,
                                       intensity=self.args.version_intensity)
                result = prober.detect_udp_service(ip, port)
                if result:
                    with self.cache_lock:
                        self.service_info_cache[cache_key] = result
                    return result
            return ""

        # For TCP ports with version detection
        if self.args.version_detection:
            prober = ServiceProber(timeout=effective_timeout,
                                   intensity=self.args.version_intensity)
            version = prober.detect_service_version(ip, port, protocol)
            if version:
                self.service_info_cache[cache_key] = version
                return version

        # Fall back to regular banner grabbing if version detection failed or not enabled
        if self.args.banner:
            try:
                # Determine socket family based on IP type
                socket_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET

                with socket.socket(socket_family, socket.SOCK_STREAM) as s:
                    s.settimeout(effective_timeout)
                    s.connect((ip, port))

                    # Try common protocols based on port
                    if port in [80, 8080, 443, 8443]:
                        s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    elif port == 21:  # FTP
                        # Just read banner, no need to send anything
                        pass
                    elif port == 25 or port == 587:  # SMTP
                        # Just read banner, no need to send anything
                        pass
                    elif port == 22:  # SSH
                        # Just read banner, no need to send anything
                        pass
                    else:
                        # Generic request that might trigger a response
                        s.send(b"\r\n\r\n")

                    try:
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        # Sanitize and limit banner length
                        banner = re.sub(r'[\x00-\x1F\x7F]', '', banner)
                        from html import escape
                        result = escape(banner)[:75]  # Use consistent max length of 75 chars
                        self.service_info_cache[cache_key] = result
                        return result
                    except socket.timeout:
                        result = "Connection established, no response"
                        self.service_info_cache[cache_key] = result
                        return result
            except (socket.error, socket.timeout) as e:
                # Log the specific error for debugging
                if self.args.verbose:
                    print(f"Error grabbing banner from {ip}:{port}: {str(e)}")

                # Check if the port closes immediately after connection
                if "refused" in str(e).lower():
                    result = "Port accepts connections but closes immediately"
                    self.service_info_cache[cache_key] = result
                    return result
                return ""

        return ""

    def _worker(self) -> None:
        """Worker thread to scan ports."""
        while True:
            try:
                target_ip, port, protocol, is_ipv6 = self.queue.get(timeout=1)
            except Empty:
                break

            # Apply rate limiting before scanning
            self._apply_rate_limit()

            try:
                is_open = False

                # Choose scan method based on protocol and args
                if protocol == 'tcp':
                    if self.args.syn:
                        is_open = self._syn_scan(target_ip, port, is_ipv6)
                    else:
                        is_open = self._tcp_connect_scan(target_ip, port, is_ipv6)
                elif protocol == 'udp':
                    is_open = self._udp_scan(target_ip, port, is_ipv6)

                # If port is open and banner grabbing or version detection is enabled
                if is_open:
                    service_info = ""
                    if self.args.banner or self.args.version_detection:
                        service_info = self._grab_banner(target_ip, port, protocol, is_ipv6)

                    if service_info and self.args.verbose:
                        with self.lock:
                            print(f"\nFound open {protocol.upper()} port {port} on {target_ip} - {service_info}")
                    elif is_open and self.args.verbose:
                        with self.lock:
                            print(f"\nFound open {protocol.upper()} port {port} on {target_ip}")

                    # If we're doing SYN scanning with version detection, we need to re-establish a full connection
                    if self.args.syn and self.args.version_detection and not service_info and protocol == 'tcp':
                        # Try to connect and get version info
                        service_info = self._grab_banner(target_ip, port, protocol, is_ipv6)
                        if service_info and self.args.verbose:
                            with self.lock:
                                print(f"\nFound open {protocol.upper()} port {port} on {target_ip} - {service_info}")
            except (socket.error, socket.timeout):
                pass

            with self.lock:
                self.scanned_ports += 1

            self.queue.task_done()

    def _print_progress(self) -> None:
        """Display scan progress."""
        while self.scanned_ports < self.total_ports:
            with self.lock:
                progress = (self.scanned_ports / self.total_ports) * 100
                elapsed = time.time() - self.start_time
                remaining = (elapsed / max(self.scanned_ports, 1)) * max((self.total_ports - self.scanned_ports), 0)

            sys.stdout.write(f"\rProgress: {self.scanned_ports}/{self.total_ports} ports scanned "
                             f"({progress:.1f}%) - Elapsed: {elapsed:.1f}s - ETA: {remaining:.1f}s")
            sys.stdout.flush()
            time.sleep(0.5)

        # Final progress update
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def _get_service_name(self, port: int) -> str:
        """Return service name for ports."""
        if port in self.common_ports:
            return self.common_ports[port]
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"

    def _determine_scan_types(self) -> str:
        # Determine scan types used
        scan_types = []
        if not self.args.udp or self.args.syn:  # Default is TCP unless only UDP is specified
            scan_types.append("SYN" if self.args.syn else "TCP")
        if self.args.udp:
            scan_types.append("UDP")
        if self.args.version_detection:
            scan_types.append("Version Detection")
        if self.args.ipv6:
            scan_types.append("IPv6")
        return " and ".join(scan_types)

    def _print_results(self, targets: List[str]) -> None:
        """Display scan results with enhanced version information."""
        elapsed = time.time() - self.start_time

        # Calculate total open ports (TCP + UDP)
        total_tcp_open = sum(len(ports) for ports in self.open_tcp_ports.values())
        total_udp_open = sum(len(ports) for ports in self.open_udp_ports.values()) if self.args.udp else 0
        total_open = total_tcp_open + total_udp_open

        # Determine scan types used
        scan_type_str = self._determine_scan_types()

        print(f"\nScan completed in {elapsed:.2f} seconds")
        print(f"Scan type: {scan_type_str}")
        print(f"Scanned {len(targets)} hosts and {self.total_ports} total ports")
        print(f"Total open ports found: {total_open} (TCP: {total_tcp_open}, UDP: {total_udp_open})\n")

        for target in targets:
            tcp_open_ports = self.open_tcp_ports[target]
            tcp_open_ports.sort()

            udp_open_ports = self.open_udp_ports.get(target, []) if self.args.udp else []
            udp_open_ports.sort()

            has_open_ports = bool(tcp_open_ports or udp_open_ports)

            # Format target display with square brackets for IPv6 addresses
            display_target = f"[{target}]" if ':' in target else target

            print(f"Target: {display_target}")
            if not has_open_ports:
                if not self.args.quiet:
                    print("No open ports found.\n")
                continue  # If there are no open ports, finish this target.

            print(f"Open ports: {len(tcp_open_ports) + len(udp_open_ports)} "
                  f"(TCP: {len(tcp_open_ports)}, UDP: {len(udp_open_ports)})")

            if self.args.os_detection and (target in self.os_results):
                os_info = self.os_results[target]
                print(f"OS Detection: {os_info['os']} (Confidence: {os_info['confidence']}%)")
                if self.args.verbose and ('reason' in os_info):
                    print(f"Detection method: {os_info['reason']}")
                print()

            # Display TCP ports if any
            if tcp_open_ports:
                print("\nTCP PORTS:")
                header = "PORT     SERVICE"
                if self.args.version_detection:
                    header += "         VERSION"
                elif self.args.banner:
                    header += "         BANNER"
                print(header)
                print("-" * (max(20, len(header))))

                for port in tcp_open_ports:
                    service = self._get_service_name(port)
                    if self.args.version_detection or self.args.banner:
                        version_info = self._grab_banner(target, port, is_ipv6=(':' in target))
                        version_display = version_info[:60] + "..." if len(version_info) > 60 else version_info
                        version_clean = version_display.replace('\r', '').replace('\n', ' ')
                        print(f"{port:<8} {service:<12} {version_clean}")
                    else:
                        print(f"{port:<8} {service}")

            # Display UDP ports if any with version detection
            if udp_open_ports:
                print("\nUDP PORTS:")
                header = "PORT     SERVICE"
                if self.args.version_detection:
                    header += "         VERSION"
                print(header)
                print("-" * (max(20, len(header))))

                for port in udp_open_ports:
                    service = self._get_service_name(port)
                    if self.args.version_detection:
                        version_info = self._grab_banner(target, port, 'udp', is_ipv6=(':' in target))
                        version_clean = version_info.replace('\r', '').replace('\n', ' ')
                        print(f"{port:<8} {service:<12} {version_clean}")
                    else:
                        print(f"{port:<8} {service}")

            print()

    def _save_results(self, targets: List[str]) -> None:
        """Save scan results to a file with version detection info."""
        try:
            with open(self.args.output, 'w') as f:
                # Determine scan types used
                scan_type_str = self._determine_scan_types()

                f.write(f"Port scan results ({scan_type_str} scan)\n")
                f.write(f"Scan date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scanned {len(targets)} hosts and {self.total_ports} total ports\n")

                total_tcp_open = sum(len(ports) for ports in self.open_tcp_ports.values())
                total_udp_open = sum(len(ports) for ports in self.open_udp_ports.values()) if self.args.udp else 0
                total_open = total_tcp_open + total_udp_open

                f.write(f"Total open ports found: {total_open} (TCP: {total_tcp_open}, UDP: {total_udp_open})\n\n")

                for target in targets:
                    # Format target display with square brackets for IPv6 addresses
                    display_target = f"[{target}]" if ':' in target else target

                    if self.args.os_detection and (target in self.os_results):
                        os_info = self.os_results[target]
                        f.write(f"OS Detection: {os_info['os']} (Confidence: {os_info['confidence']}%)\n")
                        if 'reason' in os_info:
                            f.write(f"Detection method: {os_info['reason']}\n")
                        f.write("\n")

                    tcp_open_ports = self.open_tcp_ports[target]
                    tcp_open_ports.sort()

                    udp_open_ports = self.open_udp_ports.get(target, []) if self.args.udp else []
                    udp_open_ports.sort()

                    has_open_ports = bool(tcp_open_ports or udp_open_ports)

                    f.write(f"Target: {display_target}\n")

                    if not has_open_ports:
                        f.write("No open ports found.\n")
                        f.write("\n")
                        continue  # If there are no open ports, finish this target.

                    f.write(f"Open ports: {len(tcp_open_ports) + len(udp_open_ports)} "
                            f"(TCP: {len(tcp_open_ports)}, UDP: {len(udp_open_ports)})\n")

                    # Write TCP ports if any
                    if tcp_open_ports:
                        f.write("\nTCP PORTS:\n")
                        header = "PORT     SERVICE"
                        if self.args.version_detection:
                            header += "         VERSION"
                        elif self.args.banner:
                            header += "         BANNER"
                        f.write(header + "\n")
                        f.write("-" * (max(20, len(header))) + "\n")

                        for port in tcp_open_ports:
                            service = self._get_service_name(port)
                            if self.args.version_detection or self.args.banner:
                                version_info = self._grab_banner(target, port, is_ipv6=(':' in target))
                                version_display = version_info[:60] + "..." if len(
                                    version_info) > 60 else version_info
                                version_clean = version_display.replace('\r', '').replace('\n', ' ')
                                f.write(f"{port:<8} {service:<12} {version_clean}\n")
                            else:
                                f.write(f"{port:<8} {service}\n")

                    # Write UDP ports if any
                    if udp_open_ports:
                        f.write("\nUDP PORTS:\n")
                        header = "PORT     SERVICE"
                        if self.args.version_detection:
                            header += "         VERSION"
                        f.write(header + "\n")
                        f.write("-" * (max(20, len(header))) + "\n")

                        for port in udp_open_ports:
                            service = self._get_service_name(port)
                            if self.args.version_detection:
                                version_info = self._grab_banner(target, port, 'udp', is_ipv6=(':' in target))
                                version_clean = version_info.replace('\r', '').replace('\n', ' ')
                                f.write(f"{port:<8} {service:<12} {version_clean}\n")
                            else:
                                f.write(f"{port:<8} {service}\n")
                    f.write("\n")

            print(f"\nResults saved to {self.args.output}")
        except IOError as e:
            print(f"Error saving results: {e}")

    def _save_json_results(self, targets: List[str]) -> None:
        try:
            # Determine scan types used
            scan_type_str = self._determine_scan_types()

            total_tcp = sum(len(ports) for ports in self.open_tcp_ports.values())
            total_udp = sum(len(ports) for ports in self.open_udp_ports.values()) if self.args.udp else 0
            results = ScanResult(scan_type=scan_type_str, scan_date=time.strftime('%Y-%m-%d %H:%M:%S'),
                                hosts_scanned=len(targets), ports_scanned=self.total_ports,
                                total_open=total_tcp + total_udp, targets={})

            for target in targets:
                tcp_open_ports = self.open_tcp_ports[target]
                tcp_open_ports.sort()

                udp_open_ports = self.open_udp_ports.get(target, []) if self.args.udp else []
                udp_open_ports.sort()

                target_data = {
                    "ip": target,
                    "ip_type": "ipv6" if ':' in target else "ipv4",
                    "tcp_ports": [],
                    **({"udp_ports": []} if self.args.udp else {})
                }

                if self.args.os_detection and (target in self.os_results):
                    target_data["os_detection"] = self.os_results[target]

                # Add TCP ports
                for port in tcp_open_ports:
                    service = self._get_service_name(port)
                    port_data = {
                        "port": port,
                        "service": service
                    }

                    if self.args.version_detection:
                        version_info = self._grab_banner(target, port, is_ipv6=(':' in target))
                        port_data["version"] = version_info
                    elif self.args.banner:
                        banner = self._grab_banner(target, port, is_ipv6=(':' in target))
                        port_data["banner"] = banner

                    target_data["tcp_ports"].append(port_data)

                # Add UDP ports
                if self.args.udp:
                    for port in udp_open_ports:
                        service = self._get_service_name(port)
                        port_data = {
                            "port": port,
                            "service": service
                        }

                        if self.args.version_detection:
                            version_info = self._grab_banner(target, port, 'udp', is_ipv6=(':' in target))
                            port_data["version"] = version_info

                        target_data["udp_ports"].append(port_data)

                results.targets[target] = target_data

            # Determine output filename
            json_file = self.args.output
            if not json_file.endswith('.json'):
                json_file += '.json'

            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2)

            print(f"\nJSON results saved to {json_file}")
        except IOError as e:
            print(f"Error saving JSON results: {e}")


if __name__ == '__main__':
    try:
        PortScanner()
    except KeyboardInterrupt:
        print("\nScan aborted by user")
        sys.exit(0)
    except EOFError:
        print("\nScan aborted by user")
        sys.exit(0)
