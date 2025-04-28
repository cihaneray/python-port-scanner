#!/usr/bin/python3

import ipaddress
import json
import os
import random
import socket
import sys
import threading
import time

from argparse import ArgumentParser, Namespace
from queue import Queue, Empty
from typing import List, Dict

try:
    # Try to import scapy for SYN scanning
    from scapy.all import sr1, IP, TCP, UDP, ICMP, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PortScanner:
    def __init__(self) -> None:
        self.queue: Queue = Queue()
        self.open_ports: Dict[str, List[int]] = {}
        self.open_udp_ports: Dict[str, List[int]] = {}  # Track UDP ports separately
        self.lock = threading.Lock()
        self.total_ports = 0
        self.scanned_ports = 0
        self.start_time = 0

        self.args = self.parse_arguments()

        # Validate arguments
        if self.args.threads < 1:
            print("Error: Thread count must be at least 1")
            sys.exit(1)

        if self.args.timeout <= 0:
            print("Error: Timeout must be greater than 0")
            sys.exit(1)

        # Check if SYN scan requires root/admin
        if self.args.syn and not self._is_root():
            print("Error: SYN scanning requires root/administrator privileges")
            sys.exit(1)

        # Check if UDP scan is available
        if self.args.udp:
            if not self._is_root():
                print("Error: UDP scanning requires root/administrator privileges")
                sys.exit(1)
            if not SCAPY_AVAILABLE:
                print("Error: UDP scanning requires the 'scapy' library")
                print("Please install it using: pip install scapy")
                sys.exit(1)

        # Check if scapy is available for SYN scanning
        if self.args.syn and not SCAPY_AVAILABLE:
            print("Error: SYN scanning requires the 'scapy' library")
            print("Please install it using: pip install scapy")
            sys.exit(1)

        # Load common ports from config file
        self.common_ports = self.load_port_config()

        self.scan()

    @staticmethod
    def parse_arguments() -> Namespace:
        parser = ArgumentParser(description='Advanced TCP/UDP Port Scanner')
        parser.add_argument('hosts', help='Host(s) to scan (can be hostname, IP, or CIDR notation)')
        parser.add_argument('ports', help='Port range to scan, formatted as start-end or "-" for all ports')
        parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads to use (default: 50)')
        parser.add_argument('-T', '--timeout', type=float, default=0.5, help='Timeout in seconds (default: 0.5)')
        parser.add_argument('-o', '--output', help='Output file for results')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all output except results')
        parser.add_argument('-b', '--banner', action='store_true', help='Attempt to grab banners from open ports')
        parser.add_argument('-s', '--syn', action='store_true', help='Use SYN scanning (requires root/admin)')
        parser.add_argument('-u', '--udp', action='store_true', help='Perform UDP scanning (requires root/admin)')
        parser.add_argument('--json', action='store_true', help='Output results in JSON format')
        parser.add_argument('--config', help='Path to custom port configuration file')
        parser.add_argument('--udp-retry', type=int, default=3, help='Number of retries for UDP scanning (default: 3)')

        return parser.parse_args()

    @staticmethod
    def _is_root() -> bool:
        """Check if the script is running with root/admin privileges."""
        if os.name == 'nt':  # Windows
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:  # Unix/Linux/Mac
            return os.geteuid() == 0

    def load_port_config(self) -> Dict[int, str]:
        """Load port configuration from file or use default."""
        if self.args.config:
            config_path = self.args.config
        else:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'port_config.json')

        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Convert keys to integers
                return {int(k): v for k, v in config['common_ports'].items()}
            else:
                # Return default configuration if file doesn't exist
                return self.get_default_ports()
        except (json.JSONDecodeError, KeyError, IOError) as e:
            print(f"Warning: Could not load port configuration: {e}")
            return self.get_default_ports()

    @staticmethod
    def get_default_ports() -> Dict[int, str]:
        """Return default common ports dictionary."""
        return {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP",
            389: "LDAP", 445: "SMB", 1433: "MSSQL", 1521: "Oracle DB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
            # Common UDP ports
            67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
            137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP", 162: "SNMP-TRAP",
            500: "IKE", 514: "Syslog", 520: "RIP", 1194: "OpenVPN", 1900: "SSDP",
            5353: "mDNS", 27015: "Steam", 44818: "EtherNet/IP"
        }

    def create_default_config(self, config_path: str) -> None:
        """Create default configuration file."""
        default_config = {
            "common_ports": {str(k): v for k, v in self.get_default_ports().items()}
        }

        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            print(f"Created default configuration file at {config_path}")
        except IOError as e:
            print(f"Warning: Could not create default configuration file: {e}")

    @staticmethod
    def parse_cidr(cidr: str) -> List[str]:
        """Parse CIDR notation and return list of IPs."""
        try:
            return [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
        except ValueError:
            # If not CIDR, treat as single host
            return [cidr]

    def resolve_targets(self, host_input: str) -> List[str]:
        """Resolve target host(s) from input."""
        # Check if input is CIDR notation
        if '/' in host_input:
            return self.parse_cidr(host_input)

        # Otherwise, treat as single hostname/IP
        if self.is_ip(host_input):
            return [host_input]
        else:
            try:
                ip = socket.gethostbyname(host_input)
                return [ip]
            except socket.gaierror:
                print(f"Error: Could not resolve hostname {host_input}")
                sys.exit(1)

    def is_ip(self, s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def scan(self) -> None:
        # Parse port range
        if self.args.ports == '-':
            start_port, end_port = 1, 65535
            port_list = range(1, 65536)
        else:
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
            except ValueError:
                print("Error: Invalid port format. Use start-end, comma-separated list, or a single port number.")
                sys.exit(1)

        # Resolve targets
        targets = self.resolve_targets(self.args.hosts)

        if not targets:
            print("Error: No valid targets to scan")
            sys.exit(1)

        # Initialize scan variables
        self.total_ports = len(port_list) * len(targets)
        if self.args.udp:
            self.total_ports *= 2  # Double for UDP scan
        self.scanned_ports = 0
        self.start_time = time.time()

        # Initialize open ports dictionary for each target
        for target in targets:
            self.open_ports[target] = []
            if self.args.udp:
                self.open_udp_ports[target] = []

        # Print scan information
        if not self.args.quiet:
            scan_types = []
            if not self.args.udp or self.args.syn:  # Default is TCP unless only UDP is specified
                scan_types.append("SYN" if self.args.syn else "TCP Connect")
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
                print(f"Ports: {', '.join(map(str, port_list[:10]))}{' ...' if len(port_list) > 10 else ''}")

            print(f"Number of threads: {self.args.threads}")
            print(f"Timeout: {self.args.timeout} seconds\n")

        # Fill the queue with (target, port, protocol) tuples to scan
        for target in targets:
            for port in port_list:
                # Add TCP scan task unless UDP-only scan is specified
                if not self.args.udp or self.args.syn:
                    self.queue.put((target, port, 'tcp'))

                # Add UDP scan task if UDP scanning is enabled
                if self.args.udp:
                    self.queue.put((target, port, 'udp'))

        # Start worker threads
        threads = []
        for _ in range(min(self.args.threads, self.total_ports)):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            threads.append(t)
            t.start()

        # Print progress while waiting for scan to complete
        if not self.args.quiet:
            self.print_progress()

        # Wait for all ports to be scanned
        self.queue.join()

        # Display results
        self.print_results(targets)

        # Save results if requested
        if self.args.output:
            if self.args.json:
                self.save_json_results(targets)
            else:
                self.save_results(targets)

    def tcp_connect_scan(self, target_ip: str, port: int) -> bool:
        """Test if a port is open using TCP connect scan."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.args.timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                with self.lock:
                    self.open_ports[target_ip].append(port)
                return True
        return False

    def syn_scan(self, target_ip: str, port: int) -> bool:
        """Test if a port is open using SYN scan."""
        if not SCAPY_AVAILABLE:
            return False

        # Disable scapy warnings
        conf.verb = 0

        # Send SYN packet
        src_port = random.randint(1025, 65534)
        packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")

        # Set timeout and send packet
        response = sr1(packet, timeout=self.args.timeout, verbose=0)

        # Check response
        if response and response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)

            # Check if SYN-ACK (flags=0x12) was received
            if tcp_layer.flags == 0x12:  # SYN-ACK
                # Send RST to close connection
                rst = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                sr1(rst, timeout=1, verbose=0)

                with self.lock:
                    self.open_ports[target_ip].append(port)
                return True

        return False

    def udp_scan(self, target_ip: str, port: int) -> bool:
        """Test if a UDP port is open."""
        if not SCAPY_AVAILABLE:
            return False

        # Disable scapy warnings
        conf.verb = 0

        # Use multiple retries for UDP scan since packets can be dropped
        for _ in range(self.args.udp_retry):
            # Send UDP packet with empty payload
            src_port = random.randint(1025, 65534)
            packet = IP(dst=target_ip) / UDP(sport=src_port, dport=port)

            # Send the packet and wait for response
            response = sr1(packet, timeout=self.args.timeout, verbose=0)

            # Process the response
            if response is None:
                # No response could mean open or filtered port
                # Continue to next retry
                continue

            # ICMP unreachable error (type 3) indicates closed port
            if response.haslayer(ICMP):
                icmp_type = response.getlayer(ICMP).type
                icmp_code = response.getlayer(ICMP).code

                if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                    # Port is closed or filtered
                    return False

            # If we got a UDP response, the port is definitely open
            elif response.haslayer(UDP):
                with self.lock:
                    self.open_udp_ports[target_ip].append(port)
                return True

        # If we've reached here without a definitive answer, we'll consider it potentially open
        # This is where UDP scanning is more complex than TCP - we can't be certain
        with self.lock:
            self.open_udp_ports[target_ip].append(port)
        return True

    def grab_banner(self, ip: str, port: int, protocol: str = 'tcp') -> str:
        """Attempt to grab service banner from open port."""
        if not self.args.banner or protocol == 'udp':  # Banner grabbing not supported for UDP
            return ""

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                # Try common protocols based on port
                if port in [80, 8080, 443, 8443]:
                    s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                else:
                    # Generic request that might trigger a response
                    s.send(b"\r\n\r\n")
                return s.recv(1024).decode('utf-8', errors='ignore').strip()[:50]  # Limit to 50 chars
        except:
            return ""

    def worker(self) -> None:
        """Worker thread to scan ports."""
        while True:
            try:
                target_ip, port, protocol = self.queue.get(timeout=1)  # Fixed possible deadlock
            except Empty:
                break

            try:
                is_open = False

                # Choose scan method based on protocol and args
                if protocol == 'tcp':
                    if self.args.syn:
                        is_open = self.syn_scan(target_ip, port)
                    else:
                        is_open = self.tcp_connect_scan(target_ip, port)
                elif protocol == 'udp':
                    is_open = self.udp_scan(target_ip, port)

                # If port is open and banner grabbing is enabled, try to grab banner
                # For SYN scan, we need to establish a new connection for banner grabbing
                if is_open and self.args.banner and protocol == 'tcp':
                    banner = self.grab_banner(target_ip, port, protocol)
                    if banner and self.args.verbose:
                        with self.lock:
                            print(f"\nFound open {protocol.upper()} port {port} on {target_ip} with banner: {banner}")
                elif is_open and self.args.verbose:
                    with self.lock:
                        print(f"\nFound open {protocol.upper()} port {port} on {target_ip}")
            except (socket.error, socket.timeout):
                pass

            with self.lock:
                self.scanned_ports += 1

            self.queue.task_done()

    def print_progress(self) -> None:
        """Display scan progress."""
        while not self.queue.empty():
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

    def get_service_name(self, port: int) -> str:
        """Return service name for ports."""
        if port in self.common_ports:
            return self.common_ports[port]
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"

    def print_results(self, targets: List[str]) -> None:
        """Display scan results."""
        elapsed = time.time() - self.start_time

        # Calculate total open ports (TCP + UDP)
        total_tcp_open = sum(len(ports) for ports in self.open_ports.values())
        total_udp_open = sum(len(ports) for ports in self.open_udp_ports.values()) if self.args.udp else 0
        total_open = total_tcp_open + total_udp_open

        # Determine scan types used
        scan_types = []
        if not self.args.udp or self.args.syn:  # Default is TCP unless only UDP is specified
            scan_types.append("SYN" if self.args.syn else "TCP Connect")
        if self.args.udp:
            scan_types.append("UDP")

        scan_type_str = " and ".join(scan_types)

        print(f"\nScan completed in {elapsed:.2f} seconds")
        print(f"Scan type: {scan_type_str}")
        print(f"Scanned {len(targets)} hosts and {self.total_ports} total ports")
        print(f"Total open ports found: {total_open} (TCP: {total_tcp_open}, UDP: {total_udp_open})\n")

        for target in targets:
            tcp_open_ports = self.open_ports[target]
            tcp_open_ports.sort()

            udp_open_ports = self.open_udp_ports.get(target, []) if self.args.udp else []
            udp_open_ports.sort()

            has_open_ports = bool(tcp_open_ports or udp_open_ports)

            if has_open_ports:
                print(f"Target: {target}")
                print(f"Open ports: {len(tcp_open_ports) + len(udp_open_ports)} "
                      f"(TCP: {len(tcp_open_ports)}, UDP: {len(udp_open_ports)})")

                # Display TCP ports if any
                if tcp_open_ports:
                    print("\nTCP PORTS:")
                    print("PORT     SERVICE" + ("       BANNER" if self.args.banner else ""))
                    print("-" * (20 + (50 if self.args.banner else 0)))

                    for port in tcp_open_ports:
                        service = self.get_service_name(port)
                        if self.args.banner:
                            banner = self.grab_banner(target, port)
                            banner_display = banner[:50] + "..." if len(banner) > 50 else banner
                            banner_clean = banner_display.replace('\r', '').replace('\n', ' ')
                            print(f"{port:<8} {service:<12} {banner_clean}")
                        else:
                            print(f"{port:<8} {service}")

                # Display UDP ports if any
                if udp_open_ports:
                    print("\nUDP PORTS:")
                    print("PORT     SERVICE")
                    print("-" * 20)

                    for port in udp_open_ports:
                        service = self.get_service_name(port)
                        print(f"{port:<8} {service}")

                print()
            elif not self.args.quiet:
                print(f"Target: {target}")
                print("No open ports found.\n")

    def save_results(self, targets: List[str]) -> None:
        """Save scan results to a file."""
        try:
            with open(self.args.output, 'w') as f:
                # Determine scan types used
                scan_types = []
                if not self.args.udp or self.args.syn:  # Default is TCP unless only UDP is specified
                    scan_types.append("SYN" if self.args.syn else "TCP Connect")
                if self.args.udp:
                    scan_types.append("UDP")

                scan_type_str = " and ".join(scan_types)

                f.write(f"Port scan results ({scan_type_str} scan)\n")
                f.write(f"Scan date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scanned {len(targets)} hosts and {self.total_ports} total ports\n")

                total_tcp_open = sum(len(ports) for ports in self.open_ports.values())
                total_udp_open = sum(len(ports) for ports in self.open_udp_ports.values()) if self.args.udp else 0
                total_open = total_tcp_open + total_udp_open

                f.write(f"Total open ports found: {total_open} (TCP: {total_tcp_open}, UDP: {total_udp_open})\n\n")

                for target in targets:
                    tcp_open_ports = self.open_ports[target]
                    tcp_open_ports.sort()

                    udp_open_ports = self.open_udp_ports.get(target, []) if self.args.udp else []
                    udp_open_ports.sort()

                    has_open_ports = bool(tcp_open_ports or udp_open_ports)

                    f.write(f"Target: {target}\n")
                    if has_open_ports:
                        f.write(f"Open ports: {len(tcp_open_ports) + len(udp_open_ports)} "
                                f"(TCP: {len(tcp_open_ports)}, UDP: {len(udp_open_ports)})\n")

                        # Write TCP ports if any
                        if tcp_open_ports:
                            f.write("\nTCP PORTS:\n")
                            f.write("PORT     SERVICE" + ("       BANNER" if self.args.banner else "") + "\n")
                            f.write("-" * (20 + (50 if self.args.banner else 0)) + "\n")

                            for port in tcp_open_ports:
                                service = self.get_service_name(port)
                                if self.args.banner:
                                    banner = self.grab_banner(target, port)
                                    banner_display = banner[:50] + "..." if len(banner) > 50 else banner
                                    banner_clean = banner_display.replace('\r', '').replace('\n', ' ')
                                    f.write(f"{port:<8} {service:<12} {banner_clean}\n")
                                else:
                                    f.write(f"{port:<8} {service}\n")

                        # Write UDP ports if any
                        if udp_open_ports:
                            f.write("\nUDP PORTS:\n")
                            f.write("PORT     SERVICE\n")
                            f.write("-" * 20 + "\n")

                            for port in udp_open_ports:
                                service = self.get_service_name(port)
                                f.write(f"{port:<8} {service}\n")
                    else:
                        f.write("No open ports found.\n")
                    f.write("\n")

            print(f"\nResults saved to {self.args.output}")
        except IOError as e:
            print(f"Error saving results: {e}")

    def save_json_results(self, targets: List[str]) -> None:
        """Save scan results to a JSON file."""
        try:
            # Determine scan types used
            scan_types = []
            if not self.args.udp or self.args.syn:  # Default is TCP unless only UDP is specified
                scan_types.append("SYN" if self.args.syn else "TCP Connect")
            if self.args.udp:
                scan_types.append("UDP")

            scan_type_str = " and ".join(scan_types)

            results = {
                "scan_info": {
                    "scan_type": scan_type_str,
                    "scan_date": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "hosts_scanned": len(targets),
                    "ports_scanned": self.total_ports,
                    "total_open": sum(len(ports) for ports in self.open_ports.values()) +
                                  (sum(len(ports) for ports in self.open_udp_ports.values()) if self.args.udp else 0)
                },
                "targets": {}
            }

            for target in targets:
                tcp_open_ports = self.open_ports[target]
                tcp_open_ports.sort()

                udp_open_ports = self.open_udp_ports.get(target, []) if self.args.udp else []
                udp_open_ports.sort()

                target_data = {
                    "ip": target,
                    "tcp_ports": [],
                    "udp_ports": [] if self.args.udp else None
                }

                # Add TCP ports
                for port in tcp_open_ports:
                    service = self.get_service_name(port)
                    port_data = {
                        "port": port,
                        "service": service
                    }

                    if self.args.banner:
                        banner = self.grab_banner(target, port)
                        port_data["banner"] = banner

                    target_data["tcp_ports"].append(port_data)

                # Add UDP ports
                if self.args.udp:
                    for port in udp_open_ports:
                        service = self.get_service_name(port)
                        port_data = {
                            "port": port,
                            "service": service
                        }
                        target_data["udp_ports"].append(port_data)

                results["targets"][target] = target_data

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
