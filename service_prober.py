#!/usr/bin/python3

class ServiceProber:
    """Service identification and version detection module."""

    def __init__(self, timeout=2.0, intensity=5):
        self.timeout = timeout
        self.intensity = intensity  # 0-9, higher means more probes/aggressiveness

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
        """Determine likely protocol based on port number."""
        return self.port_to_protocol.get(port, 'default')

    def detect_service_version(self, ip, port, protocol='tcp'):
        """Detect service version by sending appropriate probes."""
        # Check cache first to avoid unnecessary network calls
        cache_key = f"{ip}:{port}:{protocol}"
        if cache_key in self.service_cache:
            return self.service_cache[cache_key]

        if protocol == 'udp':
            # UDP service detection is more complex and less reliable
            result = self.detect_udp_service(port)
            self.service_cache[cache_key] = result
            return result

        # For TCP, we'll use our probe data
        service_protocol = self.get_protocol_for_port(port)

        # Special handling for HTTPS
        if service_protocol == 'https':
            result = self.probe_https(ip, port)
            self.service_cache[cache_key] = result
            return result

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
        result = "Service running"
        self.service_cache[cache_key] = result
        return result

    def send_probe(self, ip, port, probe_data, response_pattern, regex_pattern):
        """Send a probe to the service and analyze the response."""
        import re
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))

                if probe_data:  # Some probes just listen without sending
                    s.send(probe_data)

                # Receive data
                response = b""
                try:
                    response = s.recv(4096)
                except socket.timeout:
                    pass

                # If we're looking for a specific pattern and don't find it, continue
                if response_pattern and response_pattern not in response:
                    return None

                # Extract version using regex if provided
                if regex_pattern and regex_pattern != r"":
                    match = re.search(regex_pattern, response.decode('utf-8', errors='ignore'))
                    if match:
                        return match.group(1).strip()

                # If we received a response but couldn't extract a version, return a generic message
                if response:
                    # Return first line of response, cleaned up
                    first_line = response.decode('utf-8', errors='ignore').split('\n')[0].strip()
                    if first_line:
                        return first_line[:50]  # Limit length

            return None
        except (socket.error, socket.timeout):
            return None

    def probe_https(self, ip, port):
        """Special handling for HTTPS services with SSL/TLS."""
        try:
            import ssl
            import socket
            import re

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    # Get certificate info
                    cert = ssock.getpeercert(binary_form=False)

                    # Send HTTP request to get server header
                    ssock.send(
                        b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Advanced-Port-Scanner\r\nAccept: */*\r\n\r\n")
                    response = ssock.recv(4096)

                    # Try to extract server header
                    server_header = None
                    response_str = response.decode('utf-8', errors='ignore')

                    match = re.search(r"Server: ([^\r\n]+)", response_str)
                    if match:
                        server_header = match.group(1).strip()

                    # Format result
                    if server_header:
                        return f"HTTPS ({server_header})"
                    else:
                        return "HTTPS"
        except Exception:
            # If HTTPS probe fails, return generic HTTPS
            return "HTTPS"

    @staticmethod
    def detect_udp_service(port):
        """Basic UDP service detection."""
        udp_services = {
            53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
            123: "NTP", 161: "SNMP", 500: "IKE", 514: "Syslog"
        }

        return udp_services.get(port, "UDP Service")
