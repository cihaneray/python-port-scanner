#!/usr/bin/python3
"""
OS Fingerprinter Module for advanced port scanner.
Performs OS detection based on TCP/IP stack behavior.
"""
import logging
from scapy.all import IP, TCP, sr1, RandShort, ICMP, conf  # Fixed import from scapy.all

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
conf.verb = 0  # Disable verbose output


class OSFingerprinter:
    """
    Class for OS fingerprinting using TCP/IP stack behavior analysis.
    Uses techniques similar to nmap's OS detection to identify target operating systems.
    """

    def __init__(self, timeout=1.0):
        self.timeout = timeout
        self.os_signatures = self._load_os_signatures()
        self.target_ip = None  # Initialize instance variables
        self.open_ports = []

    @staticmethod
    def _load_os_signatures():
        """Load OS fingerprinting signatures."""
        # These are simplified signatures.
        return {
            "windows": {
                "syn_ack": {
                    "ttl": (124, 128),
                    "window_size": (8192, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SACK Permitted"],
                    "option_order": ["MSS", "NOP", "WScale", "Timestamp", "SACK Permitted"],
                },
                "icmp_echo": {"ttl": (120, 128), "df": True},
                "tcp_null": {"response": "none"},  # Expect no response to NULL probe on open port
                "tcp_fin": {"response": "none"},  # Expect no response to FIN probe on open port
                "confidence_weight": 0.8,
            },
            "linux_2_6": {
                "syn_ack": {
                    "ttl": (60, 64),
                    "window_size": (5840, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "SACK Permitted", "Timestamp", "NOP", "WScale"],
                    "option_order": ["MSS", "SACK Permitted", "Timestamp", "WScale"],
                },
                "icmp_echo": {"ttl": (60, 64), "df": True},
                "tcp_null": {"response": "rstack"},  # Some Linux versions respond with RST/ACK
                "tcp_fin": {"response": "rstack"},  # Some Linux versions respond with RST/ACK
                "confidence_weight": 0.75,
            },
            "macos": {
                "syn_ack": {
                    "ttl": (60, 64),
                    "window_size": (65535, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SACK Permitted"],
                    "option_order": ["MSS", "NOP", "WScale", "Timestamp", "SACK Permitted"],
                },
                "icmp_echo": {"ttl": (60, 64), "df": True},
                "tcp_null": {"response": "none"},
                "tcp_fin": {"response": "none"},
                "confidence_weight": 0.8,
            },
            "freebsd": {
                "syn_ack": {
                    "ttl": (60, 64),
                    "window_size": (65535, 65535),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "SACK Permitted", "Timestamp"],
                    "option_order": ["MSS", "NOP", "WScale", "SACK Permitted", "Timestamp"],
                },
                "icmp_echo": {"ttl": (60, 64), "df": True},
                "tcp_null": {"response": "none"},
                "tcp_fin": {"response": "none"},
                "confidence_weight": 0.7,
            },
            "cisco_ios": {
                "syn_ack": {
                    "ttl": (250, 255),
                    "window_size": (4128, 4128),
                    "df": False,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "NOP"],
                    "option_order": ["MSS", "NOP", "NOP"],
                },
                "icmp_echo": {"ttl": (250, 255), "df": False},
                "tcp_null": {"response": "rstack"},
                "tcp_fin": {"response": "rstack"},
                "confidence_weight": 0.85,
            },
            "openbsd": {
                "syn_ack": {
                    "ttl": (60, 64),
                    "window_size": (16384, 16384),
                    "df": True,
                    "tos": 0,
                    "tcp_options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp"],
                    "option_order": ["MSS", "NOP", "WScale", "Timestamp"],
                },
                "icmp_echo": {"ttl": (60, 64), "df": True},
                "tcp_null": {"response": "rst"},  # OpenBSD often responds with RST
                "tcp_fin": {"response": "rst"},  # OpenBSD often responds with RST
                "confidence_weight": 0.7,
            },
            "embedded": {
                "syn_ack": {
                    "ttl": (30, 64),
                    "window_size": (512, 5840),
                    "df": False,
                    "tos": 0,
                    "tcp_options": ["MSS"],
                    "option_order": ["MSS"],
                },
                "icmp_echo": {"ttl": (30, 64), "df": False},
                "tcp_null": {"response": "none"},
                "tcp_fin": {"response": "none"},
                "confidence_weight": 0.6,
            },
        }

    def fingerprint_os(self, target_ip, open_ports=None):
        """
        Fingerprint the OS of the target IP using multiple probes.
        Returns the most likely OS and confidence level.
        """
        self.target_ip = target_ip  # Store for later use in version detection
        self.open_ports = open_ports if open_ports else []
        results = []

        try:
            # ICMP Echo probe
            icmp_result = self._icmp_probe(target_ip)
            if icmp_result:
                results.extend(icmp_result)

            # SYN probe to open port
            probe_result = self._syn_probe(target_ip, self.open_ports)
            if probe_result:
                results.extend(probe_result)

            # TCP NULL probe to open port
            null_result = self._tcp_null_probe(target_ip, self.open_ports)
            if null_result:
                results.extend(null_result)

            # TCP FIN probe to open port
            fin_result = self._tcp_fin_probe(target_ip, self.open_ports)
            if fin_result:
                results.extend(fin_result)

            # Add other probe types here (e.g., TCP SYN-ACK, Xmas)

        except ImportError:
            return {"os": "Unknown", "confidence": 0, "reason": "Scapy library not available"}
        except Exception as e:
            logging.error(f"An error occurred during fingerprinting: {e}")
            return {"os": "Unknown", "confidence": 0, "reason": f"Error during probing: {e}"}

        # Analyze results
        return self._analyze_results(results)

    def _syn_probe(self, target_ip, open_ports):
        """Sends SYN probes to open ports."""
        results = []
        if not open_ports or len(open_ports) == 0:
            test_ports = [80, 443, 22]
        else:
            test_ports = open_ports[:5]

        for port in test_ports:
            try:
                src_port = RandShort()
                syn_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)

                if response and response.haslayer(TCP):
                    ttl = response.ttl
                    window_size = response.getlayer(TCP).window
                    df = bool(response.flags.DF)  # Fixed: Use flags.DF property instead of bit manipulation
                    tos = response.tos
                    tcp_options = [opt[0] for opt in response.getlayer(TCP).options] if response.haslayer(
                        TCP) and hasattr(response.getlayer(TCP), 'options') else []
                    # Fixed: Extract option names correctly

                    matches = self._match_signature("syn_ack", ttl, window_size, df, tos, tcp_options)
                    if matches:
                        results.extend(matches)

                    rst_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
                    sr1(rst_packet, timeout=0.5, verbose=0)
            except Exception as e:
                logging.warning(f"Error during SYN probe to port {port}: {e}")
        return results

    def _icmp_probe(self, target_ip):
        """Sends ICMP Echo request."""
        results = []
        try:
            icmp_packet = IP(dst=target_ip) / ICMP()
            response = sr1(icmp_packet, timeout=self.timeout, verbose=0)

            if response and response.haslayer(ICMP):
                ttl = response.ttl
                df = bool(response.flags.DF)  # Fixed: Use flags.DF property
                matches = self._match_signature("icmp_echo", ttl, None, df, None, None)  # Only checking TTL and DF
                if matches:
                    results.extend(matches)
        except Exception as e:
            logging.warning(f"Error during ICMP probe: {e}")
        return results

    def _tcp_null_probe(self, target_ip, open_ports):
        """Sends TCP NULL probes (no flags set) to open ports."""
        results = []
        if not open_ports or len(open_ports) == 0:
            test_ports = [80, 443, 22]
        else:
            test_ports = open_ports[:3]

        for port in test_ports:
            try:
                src_port = RandShort()
                null_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="")
                response = sr1(null_packet, timeout=self.timeout, verbose=0)

                observed_response = "none"
                if response and response.haslayer(TCP):
                    tcp_flags = response.getlayer(TCP).flags
                    if tcp_flags == 0x14:  # RST+ACK (0x14 = 20 in decimal)
                        observed_response = "rstack"
                    elif tcp_flags == 0x04:  # RST (0x04 = 4 in decimal)
                        observed_response = "rst"

                matches = self._match_tcp_probe_signature("tcp_null", observed_response)  # Fixed function name
                if matches:
                    results.extend(matches)

            except Exception as e:
                logging.warning(f"Error during TCP NULL probe to port {port}: {e}")
        return results

    def _tcp_fin_probe(self, target_ip, open_ports):
        """Sends TCP FIN probes to open ports."""
        results = []
        if not open_ports or len(open_ports) == 0:
            test_ports = [80, 443, 22]
        else:
            test_ports = open_ports[:3]

        for port in test_ports:
            try:
                src_port = RandShort()
                fin_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="F")
                response = sr1(fin_packet, timeout=self.timeout, verbose=0)

                observed_response = "none"
                if response and response.haslayer(TCP):
                    tcp_flags = response.getlayer(TCP).flags
                    if tcp_flags == 0x14:  # RST+ACK (0x14 = 20 in decimal)
                        observed_response = "rstack"
                    elif tcp_flags == 0x04:  # RST (0x04 = 4 in decimal)
                        observed_response = "rst"

                matches = self._match_tcp_probe_signature("tcp_fin", observed_response)  # Fixed function name
                if matches:
                    results.extend(matches)

            except Exception as e:
                logging.warning(f"Error during TCP FIN probe to port {port}: {e}")
        return results

    def _match_tcp_probe_signature(self, probe_type, observed_response):
        """Match observed response for TCP NULL/FIN probes against signatures."""
        matches = []
        for os_name, signature in self.os_signatures.items():
            if probe_type in signature:
                sig = signature[probe_type]
                response_match = sig.get("response") is None or (
                        observed_response is not None and sig["response"] == observed_response)

                if response_match:
                    confidence = signature.get("confidence_weight", 0.5)
                    matches.append((os_name, confidence))
        return matches

    def _match_signature(self, probe_type, ttl=None, window_size=None, df=None, tos=None, tcp_options=None):
        """Match observed characteristics against signatures for a specific probe type."""
        matches = []
        for os_name, signature in self.os_signatures.items():
            if probe_type in signature:
                sig = signature[probe_type]
                ttl_match = sig.get("ttl") is None or (ttl is not None and sig["ttl"][0] <= ttl <= sig["ttl"][1])
                win_match = sig.get("window_size") is None or (
                        window_size is not None and sig["window_size"][0] <= window_size <= sig["window_size"][1])
                df_match = sig.get("df") is None or (df is not None and sig["df"] == df)
                tos_match = sig.get("tos") is None or (tos is not None and sig["tos"] == tos)

                # Fixed option matching
                options_match = True
                if sig.get("tcp_options") is not None and tcp_options is not None:
                    # Check if all required options are present (not necessarily in order)
                    options_match = all(opt in tcp_options for opt in sig["tcp_options"])

                option_order_match = True
                if sig.get("option_order") is not None and tcp_options is not None:
                    option_order_match = self._check_option_order(sig["option_order"], tcp_options)

                if all([ttl_match, win_match, df_match, tos_match, options_match, option_order_match]):
                    confidence = signature.get("confidence_weight", 0.5)
                    matches.append((os_name, confidence))
        return matches

    @staticmethod
    def _check_option_order(expected_order, observed_options):
        """Checks if the observed TCP options contain the expected options in the specified order."""
        # Create a copy of observed options to track positions
        observed_copy = observed_options.copy()
        last_pos = -1

        for expected_opt in expected_order:
            if expected_opt not in observed_copy:
                return False

            pos = observed_copy.index(expected_opt)
            if pos <= last_pos:  # Options must appear in expected order
                return False

            last_pos = pos

        return True

    def _analyze_results(self, results):
        """Analyzes the fingerprinting results to determine the most likely OS."""
        if not results:
            return {"os": "Unknown", "confidence": 0, "reason": "Insufficient data"}

        os_votes = {}
        for os_name, confidence in results:
            os_votes[os_name] = os_votes.get(os_name, 0) + confidence

        if os_votes:
            most_likely_os = max(os_votes.items(), key=lambda x: x[1])
            os_name = most_likely_os[0]
            total_confidence = sum(os_votes.values())
            confidence_percentage = min(100, int((most_likely_os[
                                                      1] / total_confidence) * 100)) if total_confidence > 0 else 0

            # Add version detection (still basic)
            if os_name == "windows":
                version = self._detect_windows_version(self.target_ip, self.open_ports)
                if version:
                    os_name = f"{os_name} ({version})"  # Fixed: Better formatting for OS name with version

            return {"os": os_name.capitalize(), "confidence": confidence_percentage, "reason": "TCP/IP fingerprinting"}
        else:
            return {"os": "Unknown", "confidence": 0, "reason": "No matches found"}

    def _detect_windows_version(self, target_ip, open_ports):
        """Attempt to detect Windows version (very basic)."""
        try:
            # Look for SMB port (445) for Windows version hints
            if 445 in open_ports:
                src_port = RandShort()
                syn_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=445, flags="S")
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)

                if response and response.haslayer(TCP):
                    window_size = response.getlayer(TCP).window

                    # Windows version fingerprinting based on SMB behavior
                    if window_size == 8192:
                        return "Windows 7/Server 2008"
                    elif window_size == 8192 and "NOP" in str(response):
                        return "Windows 10/Server 2019"
                    elif window_size == 64240:
                        return "Windows Server 2016"
                    elif window_size > 16384:
                        return "Windows 10+"
                    else:
                        return "Windows"

                # Check for RDP port (3389)
            if 3389 in open_ports:
                # Modern Windows systems typically have RDP
                return "Windows 7+"

            return None
        except Exception as e:
            logging.warning(f"Error during Windows version detection: {e}")
            return "Windows"  # Return a general "Windows" on error
