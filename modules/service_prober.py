#!/usr/bin/python3

import re
import socket
import ssl
import logging


class ServiceProber:
    """Service identification and version detection module."""

    def __init__(self, timeout=2.0, intensity=5, log_level=logging.WARNING):
        """
        Initialize ServiceProber with detection parameters.

        Args:
            timeout (float): Socket timeout in seconds
            intensity (int): Probe intensity level (0-9)
            log_level (int): Logging level for errors and warnings
        """
        self.timeout = timeout
        self.intensity = max(0, min(9, intensity))  # Ensure intensity is between 0-9

        # Set up logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ServiceProber')

        # Cache for service probes to avoid redundant network calls
        self.service_cache = {}

        # Protocol-specific probes - each is a tuple of (probe_data, response_pattern, version_extract_regex)
        self.probes = {
            'http': [
                (b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Advanced-Port-Scanner\r\nAccept: */*\r\n\r\n",
                 b"HTTP/", r"Server: ([^\r\n]+)"),
                (b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Advanced-Port-Scanner\r\nAccept: */*\r\n\r\n",
                 b"HTTP/", r"Server: ([^\r\n]+)")
            ],
            'https': [
                # HTTPS requires SSL/TLS handshake before sending HTTP requests
                # This is handled separately in the probe_https method
            ],
            'smtp': [
                (b"EHLO advanced-port-scanner.local\r\n",
                 b"220", r"220 ([^\r\n]+)"),
                (b"HELO advanced-port-scanner.local\r\n",
                 b"220", r"220 ([^\r\n]+)")
            ],
            'pop3': [
                (b"CAPA\r\n",
                 b"+OK", r"\+OK ([^\r\n]+)"),
                (b"", b"+OK", r"\+OK ([^\r\n]+)")
            ],
            'imap': [
                (b"A001 CAPABILITY\r\n",
                 b"* CAPABILITY", r"(IMAP[^\r\n]+)"),
                (b"", b"* OK", r"\* OK ([^\r\n]+)")
            ],
            'ftp': [
                (b"", b"220", r"220[\- ]([^\r\n]+)"),
                (b"HELP\r\n", b"214", r"([^\r\n]+)")
            ],
            'ssh': [
                (b"", b"SSH", r"(SSH[^\r\n]+)")
            ],
            'telnet': [
                (b"", b"", r"([^\r\n]+)")
            ],
            'mysql': [
                (b"\x1a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x00",  # MySQL client handshake
                 b"", r"([0-9]+\.[0-9]+\.[0-9]+)")
            ],
            'mssql': [
                (b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\x04\x00\x38\x00\x01\x05\x00\x39\x00\x01\x06\x00\x3a\x00\x01\x07\x00\x3b\x00\x01",
                 b"", r"Microsoft SQL Server ([0-9]+)")
            ],
            'redis': [
                (b"INFO\r\n",
                 b"redis_version", r"redis_version:([^\r\n]+)")
            ],
            'mongodb': [
                (b"\x41\x00\x00\x00\x3a\x30\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x19\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00",
                 b"", r"version.: .([0-9]+\.[0-9]+\.[0-9]+).")
            ],
            'dns': [
                (b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03",
                 b"", r"version.bind.\s+([^\s]+)")
            ],
            'postgresql': [
                (b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
                 b"", r"PostgreSQL ([0-9]+\.[0-9]+)")
            ],
            'rdp': [
                (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
                 b"", r"")  # RDP just check connection response
            ],
            'vnc': [
                (b"RFB 003.008\n",
                 b"RFB", r"RFB ([0-9]+\.[0-9]+)")
            ],
            'ldap': [
                (b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
                 b"", r"")  # Just check LDAP response
            ],
            # Default probe for other services
            'default': [
                (b"\r\n\r\n", b"", r"([^\r\n]+)"),
                (b"HELP\r\n", b"", r"([^\r\n]+)"),
                (b"", b"", r"([^\r\n]+)")
            ]
        }

        # Common protocol port mappings
        self.port_to_protocol = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 389: 'ldap', 443: 'https',
            445: 'smb', 1433: 'mssql', 1521: 'oracle', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
            8080: 'http', 8443: 'https', 27017: 'mongodb'
        }

    def get_protocol_for_port(self, port):
        """
        Determine likely protocol based on port number.

        Args:
            port (int): Port number to check

        Returns:
            str: Protocol name or 'default' if unknown
        """
        return self.port_to_protocol.get(port, 'default')

    def detect_service_version(self, ip, port, protocol='tcp'):
        """
        Detect service version by sending appropriate probes.

        Args:
            ip (str): Target IP address
            port (int): Target port number
            protocol (str): 'tcp' or 'udp'

        Returns:
            str: Service and version information or None if detection failed
        """
        # Check cache first to avoid unnecessary network calls
        cache_key = f"{ip}:{port}:{protocol}"
        if cache_key in self.service_cache:
            return self.service_cache[cache_key]

        try:
            if protocol == 'udp':
                # UDP service detection needs actual probing
                result = self.detect_udp_service(ip, port)
                if result:
                    self.service_cache[cache_key] = result
                    return result
                return None

            # For TCP, we'll use our probe data
            service_protocol = self.get_protocol_for_port(port)

            # Special handling for HTTPS
            if service_protocol == 'https':
                result = self.probe_https(ip, port)
                if result:
                    self.service_cache[cache_key] = result
                    return result
                return None

            # Get applicable probes based on intensity
            probe_count = max(1, min(len(self.probes.get(service_protocol, [])), self.intensity))
            active_probes = self.probes.get(service_protocol, [])[:probe_count]

            # If no specific probes available, use default ones
            if not active_probes:
                active_probes = self.probes['default'][:probe_count]

            # Try each probe
            for probe_data, response_pattern, regex_pattern in active_probes:
                result = self.send_probe(ip, port, probe_data, response_pattern, regex_pattern)
                if result:
                    self.service_cache[cache_key] = result
                    return result

            # Try default probes as a fallback
            if service_protocol != 'default':
                for probe_data, response_pattern, regex_pattern in self.probes['default'][:2]:
                    result = self.send_probe(ip, port, probe_data, response_pattern, regex_pattern)
                    if result:
                        self.service_cache[cache_key] = result
                        return result

            # Cache and return generic message as fallback
            result = f"Unknown service on port {port}"
            self.service_cache[cache_key] = result
            return result

        except Exception as e:
            self.logger.error(f"Error detecting service on {ip}:{port}: {str(e)}")
            return None

    def send_probe(self, ip, port, probe_data, response_pattern, regex_pattern):
        """
        Send a probe to the service and analyze the response.

        Args:
            ip (str): Target IP address
            port (int): Target port number
            probe_data (bytes): Data to send
            response_pattern (bytes): Pattern to look for in response
            regex_pattern (str): Regex to extract version info

        Returns:
            str: Service version info or None if not detected
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                self.logger.debug(f"Connecting to {ip}:{port}")
                s.connect((ip, port))

                if probe_data:  # Some probes just listen without sending
                    self.logger.debug(f"Sending probe to {ip}:{port}")
                    s.send(probe_data)

                # Receive data
                response = b""
                try:
                    response = s.recv(4096)
                    self.logger.debug(f"Received {len(response)} bytes from {ip}:{port}")
                except socket.timeout:
                    self.logger.debug(f"Socket timeout waiting for response from {ip}:{port}")
                    pass

                # If we're looking for a specific pattern and don't find it, continue
                if response_pattern and response_pattern not in response:
                    return None

                # Extract version using regex if provided
                if regex_pattern and regex_pattern != r"":
                    try:
                        match = re.search(regex_pattern, response.decode('utf-8', errors='replace'))
                        if match:
                            return match.group(1).strip()
                    except Exception as e:
                        self.logger.warning(f"Error extracting regex from response: {str(e)}")

                # If we received a response but couldn't extract a version, return a generic message
                if response:
                    try:
                        # Return first line of response, cleaned up
                        first_line = response.decode('utf-8', errors='replace').split('\n')[0].strip()
                        if first_line:
                            return first_line[:50]  # Limit length
                    except Exception as e:
                        self.logger.warning(f"Error processing response: {str(e)}")

            return None
        except (socket.error, socket.timeout) as e:
            self.logger.debug(f"Socket error when probing {ip}:{port}: {str(e)}")
            return None
        except Exception as e:
            self.logger.warning(f"Unexpected error when probing {ip}:{port}: {str(e)}")
            return None

    def probe_https(self, ip, port):
        """
        Special handling for HTTPS services with SSL/TLS.

        Args:
            ip (str): Target IP address
            port (int): Target port number

        Returns:
            str: HTTPS service info or None if detection failed
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    # Get certificate info and use it if available
                    cert = ssock.getpeercert(binary_form=False)
                    cert_info = ""

                    # Try to extract organization information from certificate
                    if cert and 'subject' in cert:
                        for field in cert['subject']:
                            if field[0][0] == 'organizationName':
                                cert_info = f" - {field[0][1]}"
                                break

                    # Send HTTP request to get server header
                    ssock.send(
                        b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Advanced-Port-Scanner\r\nAccept: */*\r\n\r\n")
                    response = ssock.recv(4096)

                    # Try to extract server header
                    server_header = None
                    response_str = response.decode('utf-8', errors='replace')

                    match = re.search(r"Server: ([^\r\n]+)", response_str)
                    if match:
                        server_header = match.group(1).strip()

                    # Format result with both certificate and server info if available
                    if server_header:
                        return f"HTTPS ({server_header}{cert_info})"
                    elif cert_info:
                        return f"HTTPS{cert_info}"
                    else:
                        return "HTTPS"
        except Exception as e:
            self.logger.debug(f"HTTPS probe failed for {ip}:{port}: {str(e)}")
            # If HTTPS probe fails, return generic HTTPS
            return "HTTPS"

    def detect_udp_service(self, ip, port):
        """
        UDP service detection with actual probing.

        Args:
            ip (str): Target IP address
            port (int): Target port number

        Returns:
            str: UDP service info or None if detection failed
        """
        # UDP service mappings for common ports
        udp_services = {
            53: ("DNS",
                 b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03"),
            67: ("DHCP",
                 b"\x01\x01\x06\x00\x01\x23\x45\x67\x89\xAB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            123: ("NTP", b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            161: ("SNMP",
                  b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"),
            500: ("IKE",
                  b"\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00"),
            514: ("Syslog", b"<14>May 01 12:34:56 test: probe\n")
        }

        try:
            # If we have a specific probe for this port, use it
            if port in udp_services:
                service_name, probe_data = udp_services[port]

                # Create UDP socket and send probe
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(probe_data, (ip, port))

                    try:
                        # Try to receive a response
                        response, _ = s.recvfrom(4096)
                        if response:
                            return f"{service_name} (responded)"
                    except socket.timeout:
                        # No response, but we can still report the likely service
                        return service_name

            # Generic UDP probe
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                # Send a simple probe
                s.sendto(b"\r\n\r\n", (ip, port))

                try:
                    response, _ = s.recvfrom(4096)
                    if response:
                        return f"UDP Service on port {port} (responsive)"
                except socket.timeout:
                    pass

            return f"UDP Service on port {port}"

        except Exception as e:
            self.logger.debug(f"UDP probe failed for {ip}:{port}: {str(e)}")
            return None
