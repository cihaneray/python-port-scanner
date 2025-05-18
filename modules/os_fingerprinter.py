#!/usr/bin/python3
"""
Enhanced OS Fingerprinter Module for advanced port scanner.
Performs OS detection based on TCP/IP stack behavior with IPv6 support.
Incorporates service banner information for improved accuracy.
"""
import logging
import re
from typing import List, Dict, Tuple, Any, Optional

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, sr1, RandShort, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("OSFingerprinter")

# Disable scapy verbose output
conf.verb = 0


class OSFingerprinter:
    """
    Class for OS fingerprinting using TCP/IP stack behavior analysis.
    Uses techniques similar to nmap's OS detection to identify target operating systems.
    Supports both IPv4 and IPv6 addresses.
    Incorporates service banner information for improved accuracy.
    """

    def __init__(self, timeout: float = 1.0):
        """
        Initialize the fingerprinter with timeout and signature database.

        Args:
            timeout: Timeout in seconds for network probes
        """
        self.timeout = timeout
        self.os_signatures = self._load_os_signatures()
        self.banner_signatures = self._load_banner_signatures()
        self.target_ip = None  # Store target IP for later use
        self.open_ports = []  # Store open ports for targeted probing
        self.is_ipv6 = False  # Flag for IPv6 targets
        self.service_banners = {}  # Store service banners for analysis

    @staticmethod
    def _load_os_signatures() -> Dict[str, Dict[str, Any]]:
        """
        Load OS fingerprinting signatures for different operating systems.
        Returns a dictionary of OS signatures for various probe types.
        """
        # These signatures are simplified but reasonably effective
        return {
            "windows": {
                "syn_ack": {
                    "ttl_v4": (124, 128),
                    "ttl_v6": (124, 128),
                    "window_size": (8192, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SACK Permitted"],
                    "option_order": ["MSS", "NOP", "WScale", "Timestamp", "SACK Permitted"],
                    "mss_values": (1380, 1460)
                },
                "icmp_echo": {"ttl_v4": (120, 128), "ttl_v6": (120, 128), "df": True},
                "tcp_null": {"response": "none"},  # Expect no response to NULL probe on open port
                "tcp_fin": {"response": "none"},  # Expect no response to FIN probe on open port
                "confidence_weight": 0.8,
                "versions": {
                    "8192_with_timestamp": "Windows 10/11",
                    "8192_without_timestamp": "Windows 7/8",
                    "16384_with_wscale10": "Windows Server 2019/2022",
                    "14600_with_timestamp": "Windows Server 2016",
                    "64240_mss1460": "Windows Server 2012 R2",
                    "default": "Windows"
                }
            },
            "linux": {
                "syn_ack": {
                    "ttl_v4": (60, 64),
                    "ttl_v6": (60, 64),
                    "window_size": (5840, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "SACK Permitted", "Timestamp", "NOP", "WScale"],
                    "option_order": ["MSS", "SACK Permitted", "Timestamp", "WScale"],
                    "mss_values": (1380, 1460)
                },
                "icmp_echo": {"ttl_v4": (60, 64), "ttl_v6": (60, 64), "df": True},
                "tcp_null": {"response": "rstack"},  # Many Linux versions respond with RST/ACK
                "tcp_fin": {"response": "rstack"},  # Many Linux versions respond with RST/ACK
                "confidence_weight": 0.75,
                "versions": {
                    "32120_with_sack": "Ubuntu 20.04+",
                    "29200_with_timestamp": "CentOS/RHEL 8+",
                    "26847_with_wscale7": "Debian 10+",
                    "5840_with_sack": "Older Linux (2.6 kernel)",
                    "default": "Linux"
                }
            },
            "macos": {
                "syn_ack": {
                    "ttl_v4": (60, 64),
                    "ttl_v6": (60, 64),
                    "window_size": (65535, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SACK Permitted"],
                    "option_order": ["MSS", "NOP", "WScale", "Timestamp", "SACK Permitted"],
                    "mss_values": (1380, 1460)
                },
                "icmp_echo": {"ttl_v4": (60, 64), "ttl_v6": (60, 64), "df": True},
                "tcp_null": {"response": "none"},
                "tcp_fin": {"response": "none"},
                "confidence_weight": 0.8,
                "versions": {
                    "65535_with_wscale6": "macOS 11+",
                    "65535_with_wscale5": "macOS 10.15",
                    "65535_with_wscale4": "macOS 10.14",
                    "65535_with_wscale3": "macOS 10.13 or earlier",
                    "default": "macOS"
                }
            },
            "freebsd": {
                "syn_ack": {
                    "ttl_v4": (60, 64),
                    "ttl_v6": (60, 64),
                    "window_size": (65535, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "SACK Permitted", "Timestamp"],
                    "option_order": ["MSS", "NOP", "WScale", "SACK Permitted", "Timestamp"],
                    "mss_values": (1380, 1460)
                },
                "icmp_echo": {"ttl_v4": (60, 64), "ttl_v6": (60, 64), "df": True},
                "tcp_null": {"response": "none"},
                "tcp_fin": {"response": "none"},
                "confidence_weight": 0.7,
                "versions": {
                    "65535_with_wscale6": "FreeBSD 13+",
                    "65535_with_wscale7": "FreeBSD 12",
                    "65535_with_wscale4": "FreeBSD 11 or earlier",
                    "default": "FreeBSD"
                }
            },
            "cisco_ios": {
                "syn_ack": {
                    "ttl_v4": (250, 255),
                    "ttl_v6": (250, 255),
                    "window_size": (4128, 4128),
                    "df": False,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "NOP"],
                    "option_order": ["MSS", "NOP", "NOP"],
                    "mss_values": (1380, 1460)
                },
                "icmp_echo": {"ttl_v4": (250, 255), "ttl_v6": (250, 255), "df": False},
                "tcp_null": {"response": "rstack"},
                "tcp_fin": {"response": "rstack"},
                "confidence_weight": 0.85,
                "versions": {
                    "4128_simple_options": "Cisco IOS 15+",
                    "4128_no_options": "Cisco IOS 12+",
                    "default": "Cisco IOS"
                }
            },
            # Additional OS types
            "openbsd": {
                "syn_ack": {
                    "ttl_v4": (60, 64),
                    "ttl_v6": (60, 64),
                    "window_size": (16384, 16384),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp"],
                    "option_order": ["MSS", "NOP", "WScale", "Timestamp"],
                    "mss_values": (1380, 1460)
                },
                "icmp_echo": {"ttl_v4": (60, 64), "ttl_v6": (60, 64), "df": True},
                "tcp_null": {"response": "rst"},  # OpenBSD often responds with RST
                "tcp_fin": {"response": "rst"},  # OpenBSD often responds with RST
                "confidence_weight": 0.7,
                "versions": {
                    "16384_with_wscale5": "OpenBSD 7.0+",
                    "16384_with_wscale4": "OpenBSD 6.x",
                    "default": "OpenBSD"
                }
            },
            "embedded": {
                "syn_ack": {
                    "ttl_v4": (30, 64),
                    "ttl_v6": (30, 64),
                    "window_size": (512, 5840),
                    "df": False,
                    "tos": 0,
                    "tcp_options": ["MSS"],
                    "option_order": ["MSS"],
                    "mss_values": (1380, 1460)
                },
                "icmp_echo": {"ttl_v4": (30, 64), "ttl_v6": (30, 64), "df": False},
                "tcp_null": {"response": "none"},
                "tcp_fin": {"response": "none"},
                "confidence_weight": 0.6,
                "versions": {
                    "2048_mss536": "IoT Device",
                    "2048_no_options": "Embedded Linux",
                    "default": "Embedded Device"
                }
            },
        }

    @staticmethod
    def _load_banner_signatures() -> Dict[str, Dict[str, Any]]:
        """
        Load signature patterns for OS detection from service banners.
        """
        return {
            # SSH banners are extremely reliable for OS detection
            "ssh": {
                "Ubuntu": {
                    "pattern": r"SSH-\d+\.\d+-OpenSSH_[\d\.]+[p\d]*\s+Ubuntu",
                    "confidence": 0.95,
                    "version_pattern": r"Ubuntu-\d+ubuntu([\d\.]+)",
                    "version_map": {
                        "6.6.1p1": "Ubuntu 14.04",
                        "7.2p2": "Ubuntu 16.04",
                        "7.6p1": "Ubuntu 18.04",
                        "8.2p1": "Ubuntu 20.04",
                        "8.9p1": "Ubuntu 22.04",
                        "9.0p1": "Ubuntu 23.04+"
                    }
                },
                "Debian": {
                    "pattern": r"SSH-\d+\.\d+-OpenSSH_[\d\.]+[p\d]*\s+Debian",
                    "confidence": 0.95,
                    "version_pattern": r"OpenSSH_([\d\.p]+)",
                    "version_map": {
                        "6.0p1": "Debian 7",
                        "6.7p1": "Debian 8",
                        "7.4p1": "Debian 9",
                        "7.9p1": "Debian 10",
                        "8.4p1": "Debian 11",
                        "9.0p1": "Debian 12"
                    }
                },
                "CentOS/RHEL": {
                    "pattern": r"SSH-\d+\.\d+-OpenSSH_[\d\.]+",
                    "confidence": 0.8,
                    "os_pattern": r"OpenSSH_([\d\.p]+)",
                    "exclude_pattern": r"(Ubuntu|Debian|FreeBSD|OpenBSD)",
                    "version_map": {
                        "5.3p1": "CentOS/RHEL 5",
                        "6.6.1p1": "CentOS/RHEL 6",
                        "7.4p1": "CentOS/RHEL 7",
                        "8.0p1": "CentOS/RHEL 8",
                        "8.7p1": "Rocky/AlmaLinux 9"
                    }
                },
                "FreeBSD": {
                    "pattern": r"SSH-\d+\.\d+-OpenSSH_[\d\.]+\s+FreeBSD",
                    "confidence": 0.95,
                    "version_pattern": r"OpenSSH_([\d\.p]+)",
                    "version_map": {
                        "7.2p2": "FreeBSD 10.x",
                        "7.5p1": "FreeBSD 11.x",
                        "7.8p1": "FreeBSD 12.0",
                        "7.9p1": "FreeBSD 12.1/12.2",
                        "8.4p1": "FreeBSD 13.0",
                        "8.8p1": "FreeBSD 13.1+"
                    }
                },
                "OpenBSD": {
                    "pattern": r"SSH-\d+\.\d+-OpenSSH_[\d\.]+",
                    "confidence": 0.9,
                    "os_pattern": r"OpenSSH_([\d\.p]+)",
                    "exclude_pattern": r"(Ubuntu|Debian|FreeBSD)",
                    "version_map": {
                        "7.8": "OpenBSD 6.4",
                        "7.9": "OpenBSD 6.5",
                        "8.0": "OpenBSD 6.6",
                        "8.1": "OpenBSD 6.7",
                        "8.2": "OpenBSD 6.8",
                        "8.3": "OpenBSD 6.9",
                        "8.4": "OpenBSD 7.0",
                        "8.6": "OpenBSD 7.1",
                        "9.0": "OpenBSD 7.2",
                        "9.1": "OpenBSD 7.3",
                        "9.2": "OpenBSD 7.4"
                    }
                },
                "Windows": {
                    "pattern": r"SSH-\d+\.\d+-OpenSSH_for_Windows",
                    "confidence": 0.95,
                    "version": "Windows 10/11 with OpenSSH"
                },
                "Dropbear": {
                    "pattern": r"SSH-\d+\.\d+-dropbear_[\d\.]+",
                    "confidence": 0.9,
                    "os": "Embedded Linux",
                    "version_pattern": r"dropbear_([\d\.]+)",
                    "version_map": {
                        "0.5": "Older Embedded Device",
                        "2014": "Router/IoT Device",
                        "2015": "Router/IoT Device",
                        "2016": "Router/IoT Device",
                        "2017": "Router/IoT Device",
                        "2018": "Router/IoT Device",
                        "2019": "Router/IoT Device",
                        "2020": "Modern Embedded Device"
                    }
                }
            },
            # HTTP banners can provide OS information through server headers
            "http": {
                "Apache": {
                    "pattern": r"Server: Apache\/[\d\.]+ \(([^)]+)\)",
                    "confidence": 0.9,
                    "os_group": 1,
                    "os_patterns": {
                        "Ubuntu": {"pattern": r"(Ubuntu)", "os": "Ubuntu", "confidence": 0.95},
                        "Debian": {"pattern": r"(Debian)", "os": "Debian", "confidence": 0.95},
                        "CentOS": {"pattern": r"(CentOS)", "os": "CentOS", "confidence": 0.95},
                        "RHEL": {"pattern": r"(Red Hat|RedHat|RHEL)", "os": "RHEL", "confidence": 0.95},
                        "FreeBSD": {"pattern": r"(FreeBSD)", "os": "FreeBSD", "confidence": 0.95},
                        "Win32": {"pattern": r"(Win32|Win64)", "os": "Windows", "confidence": 0.95},
                    }
                },
                "Microsoft-IIS": {
                    "pattern": r"Server: Microsoft-IIS\/([\d\.]+)",
                    "confidence": 0.95,
                    "os": "Windows",
                    "version_pattern": r"Microsoft-IIS\/([\d\.]+)",
                    "version_map": {
                        "7.0": "Windows Server 2008",
                        "7.5": "Windows Server 2008 R2",
                        "8.0": "Windows Server 2012",
                        "8.5": "Windows Server 2012 R2",
                        "10.0": "Windows Server 2016/2019/2022"
                    }
                },
                "nginx": {
                    "pattern": r"Server: nginx\/([\d\.]+)",
                    "confidence": 0.7,  # Lower confidence as nginx runs on many platforms
                    "version_pattern": r"nginx\/([\d\.]+)",
                    "version_map": {
                        "1.10": "Ubuntu 16.04 (likely)",
                        "1.14": "Ubuntu 18.04 (likely)",
                        "1.18": "Ubuntu 20.04 (likely)",
                        "1.22": "Ubuntu 22.04 (likely)"
                    }
                },
                "lighttpd": {
                    "pattern": r"Server: lighttpd\/([\d\.]+)",
                    "confidence": 0.7,
                    "os": "Linux/FreeBSD (likely)"
                }
            },
            # FTP banners can sometimes reveal OS information
            "ftp": {
                "vsftpd": {
                    "pattern": r"220 \(vsFTPd ([\d\.]+)\)",
                    "confidence": 0.85,
                    "os": "Linux"
                },
                "Microsoft FTP": {
                    "pattern": r"220 Microsoft FTP Service",
                    "confidence": 0.95,
                    "os": "Windows"
                },
                "ProFTPD": {
                    "pattern": r"220 ProFTPD ([\d\.]+)",
                    "confidence": 0.7,
                    "os": "Unix/Linux"
                }
            },
            # SMTP banners
            "smtp": {
                "Postfix": {
                    "pattern": r"220.*Postfix",
                    "confidence": 0.85,
                    "os": "Linux (likely)"
                },
                "Microsoft SMTP": {
                    "pattern": r"220.*Microsoft ESMTP",
                    "confidence": 0.95,
                    "os": "Windows"
                },
                "Exchange": {
                    "pattern": r"220.*Microsoft Exchange",
                    "confidence": 0.95,
                    "os": "Windows Server"
                }
            }
        }

    def fingerprint_os(self, target_ip: str, open_ports: Optional[List[int]] = None,
                           service_banners: Optional[Dict[str, Dict[int, str]]] = None,
                           is_ipv6: Optional[bool] = None) -> Dict[str, Any]:
        """
        Fingerprint the OS of the target IP using multiple TCP/IP stack probes and service banners.
        Supports both IPv4 and IPv6 addresses.

        Args:
            target_ip: Target IP address (IPv4 or IPv6)
            open_ports: List of open ports to use for probing (optional)
            service_banners: Dictionary of service banners by protocol and port (optional)

        Returns:
            Dictionary with OS information and confidence level
        """
        if not SCAPY_AVAILABLE:
            return {"os": "Unknown", "confidence": 0, "reason": "Scapy library not available"}

        self.target_ip = target_ip
        self.open_ports = open_ports or []
        self.is_ipv6 = is_ipv6 if is_ipv6 is not None else ':' in target_ip
        self.service_banners = service_banners or {}

        # First check if we have banner information that can definitively identify the OS
        banner_os = self._analyze_service_banners()
        if banner_os and banner_os.get("confidence", 0) >= 85:
            banner_os["reason"] = "Service banner identification"
            return banner_os

        # If no high-confidence banner match, perform TCP/IP fingerprinting
        results = []
        probe_errors = []

        try:
            # ICMP Echo probe
            icmp_result = self._icmp_probe(target_ip)
            if icmp_result:
                results.extend(icmp_result)

            # Select ports for testing
            probe_ports = self._select_probe_ports(open_ports)

            # SYN probe to open port(s)
            syn_results = []
            for port in probe_ports:
                syn_result = self._syn_probe(target_ip, port)
                if syn_result:
                    syn_results.extend(syn_result)

            if syn_results:
                results.extend(syn_results)

            # Only attempt TCP NULL and FIN probes if we have open ports
            if probe_ports:
                # TCP NULL probe to open port
                for port in probe_ports[:2]:  # Limit to first 2 ports
                    null_result = self._tcp_null_probe(target_ip, port)
                    if null_result:
                        results.extend(null_result)

                # TCP FIN probe to open port
                for port in probe_ports[:2]:  # Limit to first 2 ports
                    fin_result = self._tcp_fin_probe(target_ip, port)
                    if fin_result:
                        results.extend(fin_result)

        except Exception as e:
            probe_errors.append(str(e))
            logger.error(f"Error during OS fingerprinting of {target_ip}: {e}")

        # Analyze TCP/IP fingerprinting results
        tcpip_os = self._analyze_results(results)

        # If we have banner information but with lower confidence, combine with TCP/IP results
        if banner_os and banner_os.get("confidence", 0) < 85:
            combined_os = self._combine_fingerprinting_results(tcpip_os, banner_os)
            if probe_errors and combined_os["confidence"] < 50:
                combined_os["probe_errors"] = probe_errors
            return combined_os

        # Add error information if there were problems during probing
        if probe_errors and tcpip_os["confidence"] < 50:
            tcpip_os["probe_errors"] = probe_errors

        return tcpip_os

    def _analyze_service_banners(self) -> Optional[Dict[str, Any]]:
        """
        Analyze service banners to identify the operating system.
        Returns OS information with confidence level, or None if no match.
        """
        if not self.service_banners:
            return None

        banner_results = []

        # Process SSH banners (most reliable)
        if "tcp" in self.service_banners:
            tcp_banners = self.service_banners["tcp"]

            # Check SSH banners (port 22)
            if 22 in tcp_banners and tcp_banners[22]:
                ssh_banner = tcp_banners[22]
                ssh_match = self._match_ssh_banner(ssh_banner)
                if ssh_match:
                    banner_results.append(ssh_match)

            # Check HTTP banners (ports 80, 443, 8080, 8443)
            http_ports = [p for p in [80, 443, 8080, 8443] if p in tcp_banners and tcp_banners[p]]
            for port in http_ports:
                http_banner = tcp_banners[port]
                http_match = self._match_http_banner(http_banner)
                if http_match:
                    banner_results.append(http_match)

            # Check FTP banners (port 21)
            if 21 in tcp_banners and tcp_banners[21]:
                ftp_banner = tcp_banners[21]
                ftp_match = self._match_ftp_banner(ftp_banner)
                if ftp_match:
                    banner_results.append(ftp_match)

            # Check SMTP banners (ports 25, 587)
            smtp_ports = [p for p in [25, 587] if p in tcp_banners and tcp_banners[p]]
            for port in smtp_ports:
                smtp_banner = tcp_banners[port]
                smtp_match = self._match_smtp_banner(smtp_banner)
                if smtp_match:
                    banner_results.append(smtp_match)

        # Process any other protocol banners here

        # If we have banner results, return the one with the highest confidence
        if banner_results:
            return max(banner_results, key=lambda x: x["confidence"])

        return None

    def _match_ssh_banner(self, banner: str) -> Optional[Dict[str, Any]]:
        """Match SSH banner against known patterns to identify OS."""
        if not banner:
            return None

        ssh_signatures = self.banner_signatures.get("ssh", {})
        for os_type, signature in ssh_signatures.items():
            pattern = signature.get("pattern")
            if pattern and re.search(pattern, banner, re.IGNORECASE):
                # Check exclude pattern if it exists
                exclude_pattern = signature.get("exclude_pattern")
                if exclude_pattern and re.search(exclude_pattern, banner, re.IGNORECASE):
                    continue

                confidence = signature.get("confidence", 0.7)

                # Try to extract version information
                os_version = os_type
                version_pattern = signature.get("version_pattern")

                if version_pattern:
                    version_match = re.search(version_pattern, banner)
                    if version_match:
                        version_str = version_match.group(1)
                        version_map = signature.get("version_map", {})

                        # Look for exact or closest match in version map
                        if version_str in version_map:
                            os_version = f"{os_type} ({version_map[version_str]})"
                        else:
                            # Try to find the closest version match
                            best_match = None
                            for v in version_map:
                                if version_str.startswith(v):
                                    if best_match is None or len(v) > len(best_match):
                                        best_match = v

                            if best_match:
                                os_version = f"{os_type} ({version_map[best_match]})"

                # If a fixed version is specified in the signature
                elif "version" in signature:
                    os_version = f"{os_type} ({signature['version']})"
                elif "os" in signature:
                    os_version = signature["os"]

                return {
                    "os": os_version,
                    "confidence": int(confidence * 100),
                    "source": "SSH banner"
                }

        return None

    def _match_http_banner(self, banner: str) -> Optional[Dict[str, Any]]:
        """Match HTTP banner against known patterns to identify OS."""
        if not banner:
            return None

        http_signatures = self.banner_signatures.get("http", {})
        for server_type, signature in http_signatures.items():
            pattern = signature.get("pattern")
            if pattern and re.search(pattern, banner, re.IGNORECASE):
                confidence = signature.get("confidence", 0.7)

                # If there's a direct OS mapping
                if "os" in signature:
                    os_version = signature["os"]

                    # Try to extract version information
                    version_pattern = signature.get("version_pattern")
                    if version_pattern:
                        version_match = re.search(version_pattern, banner)
                        if version_match:
                            version_str = version_match.group(1)
                            version_map = signature.get("version_map", {})

                            if version_str in version_map:
                                os_version = f"{os_version} ({version_map[version_str]})"
                            elif version_str:
                                os_version = f"{os_version} (server version {version_str})"

                    return {
                        "os": os_version,
                        "confidence": int(confidence * 100),
                        "source": "HTTP server banner"
                    }

                # If we need to extract OS from group in regex
                elif "os_group" in signature:
                    group_match = re.search(pattern, banner, re.IGNORECASE)
                    if group_match and group_match.group(signature["os_group"]):
                        os_string = group_match.group(signature["os_group"])

                        # Check for specific OS patterns in the extracted string
                        os_patterns = signature.get("os_patterns", {})
                        for os_name, os_pattern_data in os_patterns.items():
                            if re.search(os_pattern_data["pattern"], os_string, re.IGNORECASE):
                                return {
                                    "os": os_pattern_data["os"],
                                    "confidence": int(os_pattern_data.get("confidence", confidence) * 100),
                                    "source": "HTTP server banner"
                                }

                        # If no specific OS pattern matched, use the extracted string
                        return {
                            "os": os_string,
                            "confidence": int(confidence * 80),  # Slightly lower confidence
                            "source": "HTTP server banner"
                        }

        return None

    def _match_ftp_banner(self, banner: str) -> Optional[Dict[str, Any]]:
        """Match FTP banner against known patterns to identify OS."""
        if not banner:
            return None

        ftp_signatures = self.banner_signatures.get("ftp", {})
        for server_type, signature in ftp_signatures.items():
            pattern = signature.get("pattern")
            if pattern and re.search(pattern, banner, re.IGNORECASE):
                confidence = signature.get("confidence", 0.7)
                os_name = signature.get("os", server_type)

                return {
                    "os": os_name,
                    "confidence": int(confidence * 100),
                    "source": "FTP banner"
                }

        return None

    def _match_smtp_banner(self, banner: str) -> Optional[Dict[str, Any]]:
        """Match SMTP banner against known patterns to identify OS."""
        if not banner:
            return None

        smtp_signatures = self.banner_signatures.get("smtp", {})
        for server_type, signature in smtp_signatures.items():
            pattern = signature.get("pattern")
            if pattern and re.search(pattern, banner, re.IGNORECASE):
                confidence = signature.get("confidence", 0.7)
                os_name = signature.get("os", server_type)

                return {
                    "os": os_name,
                    "confidence": int(confidence * 100),
                    "source": "SMTP banner"
                }

        return None

    def _combine_fingerprinting_results(self, tcpip_result: Dict[str, Any],
                                        banner_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combine TCP/IP fingerprinting results with banner analysis results.
        Prioritizes higher confidence results and reconciles conflicting information.
        """
        tcpip_os = tcpip_result.get("os", "Unknown")
        tcpip_confidence = tcpip_result.get("confidence", 0)

        banner_os = banner_result.get("os", "Unknown")
        banner_confidence = banner_result.get("confidence", 0)

        # If both methods identified the same OS family, use the one with higher confidence
        # but combine version information if possible
        if self._same_os_family(tcpip_os, banner_os):
            if banner_confidence >= tcpip_confidence:
                result = banner_result.copy()
            else:
                result = tcpip_result.copy()

            result["reason"] = "Combined TCP/IP and service banner analysis"
            return result

        # If different OS families were identified, use the one with significantly higher confidence
        if banner_confidence > tcpip_confidence + 20:
            result = banner_result.copy()
            result["alternative_os"] = tcpip_result["os"]
            result["reason"] = "Service banner analysis (higher confidence than TCP/IP)"
            return result

        if tcpip_confidence > banner_confidence + 10:
            result = tcpip_result.copy()
            result["alternative_os"] = banner_result["os"]
            result["reason"] = "TCP/IP fingerprinting (higher confidence than banner)"
            return result

        # If confidences are similar but disagree, slightly favor banner results as they're more explicit
        if banner_confidence >= tcpip_confidence - 10:
            result = banner_result.copy()
            result["alternative_os"] = tcpip_result["os"]
            result["reason"] = "Service banner analysis with TCP/IP validation"
            # Average the confidences but cap at banner confidence
            result["confidence"] = min(banner_confidence,
                                       int((banner_confidence * 0.7 + tcpip_confidence * 0.3)))
            return result

        # Default case, use TCP/IP result but note banner alternative
        result = tcpip_result.copy()
        result["alternative_os"] = banner_result["os"]
        result["reason"] = "TCP/IP fingerprinting with banner analysis"
        return result

    @staticmethod
    def _same_os_family(os1: str, os2: str) -> bool:
        """Check if two OS strings belong to the same OS family."""
        os1_lower = os1.lower()
        os2_lower = os2.lower()

        # Define OS families
        linux_terms = ["linux", "ubuntu", "debian", "centos", "rhel", "fedora", "red hat"]
        windows_terms = ["windows", "microsoft", "win"]
        bsd_terms = ["bsd", "freebsd", "openbsd", "netbsd"]
        mac_terms = ["mac", "macos", "os x", "darwin"]

        # Check if both belong to the same family
        for terms in [linux_terms, windows_terms, bsd_terms, mac_terms]:
            if any(term in os1_lower for term in terms) and any(term in os2_lower for term in terms):
                return True

        return False

    @staticmethod
    def _select_probe_ports(open_ports: Optional[List[int]]) -> List[int]:
        """
        Select appropriate ports for probing based on open ports found.
        Prioritizes common service ports.

        Args:
            open_ports: List of open ports discovered during scanning

        Returns:
            List of ports to use for OS fingerprinting probes
        """
        if not open_ports or len(open_ports) == 0:
            return [80, 443, 22, 21, 25]  # Default ports to try

        # Define priority ports (common services are more reliable for fingerprinting)
        priority_ports = [22, 80, 443, 21, 25, 23, 3389, 445, 139, 8080]

        # Select ports by priority
        selected_ports = []

        # First add any priority ports that are open
        for port in priority_ports:
            if port in open_ports and port not in selected_ports:
                selected_ports.append(port)

        # Then add other open ports until we have enough
        for port in open_ports:
            if port not in selected_ports:
                selected_ports.append(port)
            if len(selected_ports) >= 5:  # Limit to 5 ports for efficiency
                break

        return selected_ports

    def _syn_probe(self, target_ip: str, port: int) -> List[Tuple[str, float]]:
        """
        Sends SYN probe to a specific port and analyzes the response.
        Supports both IPv4 and IPv6.

        Args:
            target_ip: Target IP address
            port: Port number to probe

        Returns:
            List of tuples with (os_name, confidence)
        """
        results = []
        try:
            src_port = RandShort()

            # Create the appropriate packet based on IP version
            if self.is_ipv6:
                syn_packet = IPv6(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")
            else:
                syn_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")

            # Send packet and wait for response
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if response and response.haslayer(TCP):
                # Extract TCP/IP characteristics
                ttl = response.hlim if self.is_ipv6 else response.ttl
                window_size = response.getlayer(TCP).window
                df = False if self.is_ipv6 else bool(response.flags.DF)
                tos = response.tc if self.is_ipv6 else response.tos

                # Extract and analyze TCP options
                tcp_options = []
                tcp_options_raw = []
                if response.haslayer(TCP) and hasattr(response.getlayer(TCP), 'options'):
                    tcp_options_raw = response.getlayer(TCP).options
                    tcp_options = [opt[0] for opt in tcp_options_raw]

                # Get MSS value if present
                mss_value = None
                for opt_name, opt_value in tcp_options_raw:
                    if opt_name == 'MSS':
                        mss_value = opt_value
                        break

                # Get window scale value if present
                wscale_value = None
                for opt_name, opt_value in tcp_options_raw:
                    if opt_name == 'WScale':
                        wscale_value = opt_value
                        break

                # Store these details for version detection
                self.last_syn_response = {
                    "window_size": window_size,
                    "mss_value": mss_value,
                    "wscale_value": wscale_value,
                    "has_timestamp": "Timestamp" in tcp_options,
                    "has_sack": "SACK Permitted" in tcp_options
                }

                # Match against signatures
                matches = self._match_signature(
                    "syn_ack", ttl, window_size, df, tos, tcp_options, mss_value
                )

                if matches:
                    results.extend(matches)

                # Send RST packet to clean up the connection
                if self.is_ipv6:
                    rst_packet = IPv6(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                else:
                    rst_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")

                sr1(rst_packet, timeout=0.5, verbose=0)

        except Exception as e:
            logger.warning(f"Error during SYN probe to {target_ip}:{port}: {e}")

        return results

    def _icmp_probe(self, target_ip: str) -> List[Tuple[str, float]]:
        """
        Sends ICMP Echo request and analyzes the response.
        Uses ICMPv6 for IPv6 addresses.

        Args:
            target_ip: Target IP address

        Returns:
            List of tuples with (os_name, confidence)
        """
        results = []
        try:
            # Create the appropriate ICMP packet based on IP version
            if self.is_ipv6:
                icmp_packet = IPv6(dst=target_ip) / ICMPv6EchoRequest()
            else:
                icmp_packet = IP(dst=target_ip) / ICMP()

            # Send packet and wait for response
            response = sr1(icmp_packet, timeout=self.timeout, verbose=0)

            if response:
                # Extract characteristics based on IP version
                if self.is_ipv6 and response.haslayer(ICMPv6EchoReply):
                    ttl = response.hlim
                    df = False  # No DF flag in IPv6
                elif not self.is_ipv6 and response.haslayer(ICMP):
                    ttl = response.ttl
                    df = bool(response.flags.DF)
                else:
                    return results  # No valid ICMP response

                # Match against signatures
                ttl_key = "ttl_v6" if self.is_ipv6 else "ttl_v4"
                matches = []

                for os_name, signature in self.os_signatures.items():
                    if "icmp_echo" in signature:
                        sig = signature["icmp_echo"]

                        # Check TTL match based on IP version
                        ttl_match = False
                        if ttl_key in sig:
                            ttl_match = sig[ttl_key][0] <= ttl <= sig[ttl_key][1]

                        # Check DF flag (IPv4 only)
                        df_match = True
                        if not self.is_ipv6 and "df" in sig:
                            df_match = sig["df"] == df

                        if ttl_match and df_match:
                            confidence = signature.get("confidence_weight", 0.5) * 0.8  # ICMP is less reliable
                            matches.append((os_name, confidence))

                results.extend(matches)

        except Exception as e:
            logger.warning(f"Error during ICMP probe to {target_ip}: {e}")

        return results

    def _tcp_null_probe(self, target_ip: str, port: int) -> List[Tuple[str, float]]:
        """
        Sends TCP NULL probe (no flags set) and analyzes the response.
        Supports both IPv4 and IPv6.

        Args:
            target_ip: Target IP address
            port: Port number to probe

        Returns:
            List of tuples with (os_name, confidence)
        """
        results = []
        try:
            src_port = RandShort()

            # Create the appropriate packet based on IP version
            if self.is_ipv6:
                null_packet = IPv6(dst=target_ip) / TCP(sport=src_port, dport=port, flags="")
            else:
                null_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="")

            # Send packet and wait for response
            response = sr1(null_packet, timeout=self.timeout, verbose=0)

            # Determine response type
            observed_response = "none"
            if response and response.haslayer(TCP):
                tcp_flags = response.getlayer(TCP).flags
                if tcp_flags == 0x14:  # RST+ACK (0x14 = 20 in decimal)
                    observed_response = "rstack"
                elif tcp_flags == 0x04:  # RST (0x04 = 4 in decimal)
                    observed_response = "rst"

            # Match against signatures
            matches = self._match_tcp_probe_signature("tcp_null", observed_response)
            if matches:
                results.extend(matches)

        except Exception as e:
            logger.warning(f"Error during TCP NULL probe to {target_ip}:{port}: {e}")

        return results

    def _tcp_fin_probe(self, target_ip: str, port: int) -> List[Tuple[str, float]]:
        """
        Sends TCP FIN probe and analyzes the response.
        Supports both IPv4 and IPv6.

        Args:
            target_ip: Target IP address
            port: Port number to probe

        Returns:
            List of tuples with (os_name, confidence)
        """
        results = []
        try:
            src_port = RandShort()

            # Create the appropriate packet based on IP version
            if self.is_ipv6:
                fin_packet = IPv6(dst=target_ip) / TCP(sport=src_port, dport=port, flags="F")
            else:
                fin_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="F")

            # Send packet and wait for response
            response = sr1(fin_packet, timeout=self.timeout, verbose=0)

            # Determine response type
            observed_response = "none"
            if response and response.haslayer(TCP):
                tcp_flags = response.getlayer(TCP).flags
                if tcp_flags == 0x14:  # RST+ACK (0x14 = 20 in decimal)
                    observed_response = "rstack"
                elif tcp_flags == 0x04:  # RST (0x04 = 4 in decimal)
                    observed_response = "rst"

            # Match against signatures
            matches = self._match_tcp_probe_signature("tcp_fin", observed_response)
            if matches:
                results.extend(matches)

        except Exception as e:
            logger.warning(f"Error during TCP FIN probe to {target_ip}:{port}: {e}")

        return results

    def _match_tcp_probe_signature(self, probe_type: str, observed_response: str) -> List[Tuple[str, float]]:
        """
        Match observed response for TCP NULL/FIN probes against signatures.

        Args:
            probe_type: Type of probe ("tcp_null" or "tcp_fin")
            observed_response: Observed response type

        Returns:
            List of tuples with (os_name, confidence)
        """
        matches = []
        for os_name, signature in self.os_signatures.items():
            if probe_type in signature:
                sig = signature[probe_type]
                response_match = sig.get("response") is None or (
                        observed_response is not None and sig["response"] == observed_response)

                if response_match:
                    confidence = signature.get("confidence_weight", 0.5) * 0.6  # Less weight for these probes
                    matches.append((os_name, confidence))
        return matches

    def _match_signature(self, probe_type: str, ttl=None, window_size=None, df=None,
                         tos=None, tcp_options=None, mss_value=None) -> List[Tuple[str, float]]:
        """
        Match observed characteristics against signatures for a specific probe type.

        Args:
            probe_type: Type of probe
            ttl: Time to Live value
            window_size: TCP window size
            df: Don't Fragment flag
            tos: Type of Service
            tcp_options: List of TCP options
            mss_value: MSS value if present

        Returns:
            List of tuples with (os_name, confidence)
        """
        matches = []
        ttl_key = "ttl_v6" if self.is_ipv6 else "ttl_v4"

        for os_name, signature in self.os_signatures.items():
            if probe_type in signature:
                sig = signature[probe_type]

                # Check TTL match based on IP version
                ttl_match = True
                if ttl is not None and ttl_key in sig:
                    ttl_match = sig[ttl_key][0] <= ttl <= sig[ttl_key][1]

                # Check window size
                win_match = True
                if window_size is not None and "window_size" in sig:
                    win_match = sig["window_size"][0] <= window_size <= sig["window_size"][1]

                # Check DF flag (IPv4 only)
                df_match = True
                if not self.is_ipv6 and df is not None and "df" in sig:
                    df_match = sig["df"] == df

                # Check ToS/Traffic Class
                tos_match = True
                if tos is not None and "tos" in sig:
                    tos_match = sig["tos"] == tos

                # Check TCP options
                options_match = True
                if tcp_options is not None and "tcp_options" in sig:
                    # Check if all required options are present (not necessarily in order)
                    required_options = set(sig["tcp_options"])
                    observed_options = set(tcp_options)
                    options_match = required_options.issubset(observed_options)

                # Check option order if specified
                option_order_match = True
                if tcp_options is not None and "option_order" in sig:
                    option_order_match = self._check_option_order(sig["option_order"], tcp_options)

                # Check MSS value if present
                mss_match = True
                if mss_value is not None and "mss_values" in sig:
                    mss_match = sig["mss_values"][0] <= mss_value <= sig["mss_values"][1]

                # Calculate match score
                if all([ttl_match, win_match, df_match, tos_match, options_match, option_order_match, mss_match]):
                    # Calculate a weighted confidence based on how many criteria matched
                    match_count = sum([ttl_match, win_match, df_match, tos_match, options_match,
                                       option_order_match, mss_match])
                    total_checks = 7 - (1 if self.is_ipv6 else 0)  # Adjust for IPv6 which doesn't have DF
                    match_ratio = match_count / total_checks

                    base_confidence = signature.get("confidence_weight", 0.5)
                    confidence = base_confidence * match_ratio

                    matches.append((os_name, confidence))

        return matches

    @staticmethod
    def _check_option_order(expected_order: List[str], observed_options: List[str]) -> bool:
        """
        Checks if the observed TCP options contain the expected options in the specified order.

        Args:
            expected_order: List of expected options in order
            observed_options: List of observed options

        Returns:
            True if options appear in the expected order, False otherwise
        """
        # Create a copy of observed options to track positions
        observed_copy = observed_options.copy()
        last_pos = -1

        for expected_opt in expected_order:
            if expected_opt not in observed_copy:
                return False

            # Find position of current option
            try:
                curr_pos = observed_copy.index(expected_opt, last_pos + 1)
            except ValueError:
                # If not found after last position, search from beginning
                try:
                    curr_pos = observed_copy.index(expected_opt)
                    # This option was found but out of order
                    if curr_pos <= last_pos:
                        return False
                except ValueError:
                    return False

            last_pos = curr_pos

        return True

    def _analyze_results(self, results: List[Tuple[str, float]]) -> Dict[str, Any]:
        """
        Analyzes the fingerprinting results to determine the most likely OS.

        Args:
            results: List of (os_name, confidence) tuples from various probes

        Returns:
            Dictionary with OS information and confidence level
        """
        if not results:
            return {"os": "Unknown", "confidence": 0, "reason": "Insufficient data"}

        # Count and weight OS votes
        os_votes = {}
        for os_name, confidence in results:
            os_votes[os_name] = os_votes.get(os_name, 0) + confidence

        if os_votes:
            # Find the OS with the highest confidence
            most_likely_os_name, highest_confidence = max(os_votes.items(), key=lambda x: x[1])

            # Calculate overall confidence percentage
            total_confidence = sum(os_votes.values())
            confidence_percentage = min(100, int((highest_confidence / total_confidence) * 100)) \
                if total_confidence > 0 else 0

            # Add version detection
            os_with_version = self._detect_os_version(most_likely_os_name)

            return {
                "os": os_with_version.capitalize(),
                "confidence": confidence_percentage,
                "reason": "TCP/IP fingerprinting",
                "details": {
                    "top_matches": dict(sorted(os_votes.items(), key=lambda x: x[1], reverse=True)[:3])
                }
            }
        else:
            return {"os": "Unknown", "confidence": 0, "reason": "No matches found"}

    def _detect_os_version(self, os_name: str) -> str:
        """
        Attempt to detect a more specific OS version based on the identified OS family.

        Args:
            os_name: Base OS name

        Returns:
            OS name with version information if available
        """
        if os_name not in self.os_signatures or not hasattr(self, 'last_syn_response'):
            return os_name

        # Get version signatures for this OS
        if "versions" not in self.os_signatures[os_name]:
            return os_name

        versions = self.os_signatures[os_name]["versions"]

        # Extract characteristics from last SYN response
        window_size = self.last_syn_response.get("window_size")
        has_timestamp = self.last_syn_response.get("has_timestamp")
        has_sack = self.last_syn_response.get("has_sack")
        mss_value = self.last_syn_response.get("mss_value")
        wscale_value = self.last_syn_response.get("wscale_value")

        # Generate keys to check against version signatures
        keys_to_check = []

        # Window size is a good indicator
        if window_size:
            key = f"{window_size}"

            # Add modifiers
            if has_timestamp:
                key += "_with_timestamp"
            else:
                key += "_without_timestamp"

            keys_to_check.append(key)

            # Try with specific MSS
            if mss_value:
                keys_to_check.append(f"{window_size}_mss{mss_value}")

            # Try with specific WScale
            if wscale_value is not None:
                keys_to_check.append(f"{window_size}_with_wscale{wscale_value}")

            # Try with SACK
            if has_sack:
                keys_to_check.append(f"{window_size}_with_sack")

            # Try generic options
            if not has_timestamp and not has_sack and wscale_value is None:
                keys_to_check.append(f"{window_size}_no_options")
            elif has_timestamp or has_sack or wscale_value is not None:
                keys_to_check.append(f"{window_size}_simple_options")

        # Check if any keys match known versions
        for key in keys_to_check:
            if key in versions:
                return f"{os_name} ({versions[key]})"

        # Return generic version if specified
        if "default" in versions:
            return f"{os_name} ({versions['default']})"

        return os_name