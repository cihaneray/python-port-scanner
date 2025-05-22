# Advanced Port Scanner
[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.6+](https://img.shields.io/badge/Python-3.6+-blueviolet.svg)](https://www.python.org/downloads/)
[![Maintenance: Active](https://img.shields.io/badge/Maintenance-Active-success.svg)](https://github.com/yourusername/advanced-port-scanner)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20macOS-orange.svg)]()

A versatile, **multithreaded** port scanner written in **Python** that supports **TCP** Connect, **SYN**, and **UDP** scanning methods. This tool allows you to scan for open ports on target hosts, with support for individual hosts, IP addresses, and **CIDR** notation. Fully compatible with both **IPv4** and **IPv6** addresses.
```
░▒▓███████▓▒░░▒▓██████████████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
```

## Features

- **Multiple scanning techniques**: TCP Connect, SYN, and UDP scanning
- **Flexible target specification**: Scan individual hosts, IPs, or entire subnets using CIDR notation
- **Full IPv6 support**: Scan both IPv4 and IPv6 addresses with all scanning methods
- **Versatile port selection**: Scan single ports, port ranges, comma-separated port lists, or all ports
- **Performance optimized**: Multithreaded scanning for improved speed
- **Service identification**: Automatic detection of common services on open ports
- **Banner grabbing**: Identify specific service versions running on open ports
- **Real-time feedback**: Progress reporting with estimated time remaining
- **Output options**: Save results as plain text or JSON format
- **OS fingerprinting**: Accurate operating system detection using TCP/IP stack behavior and service banners
- **Rate limiting**: Control scan speed to avoid overwhelming targets
- **Customizable settings**: Adjustable timeouts, thread counts, and retry attempts
- **Detail control**: Verbose and quiet modes for different output levels
- **Service database**: Customizable port service definitions via external configuration

## Requirements

- Python 3.6 or higher
- For SYN and UDP scanning:
  - Root/Administrator privileges
  - Scapy library
- No external dependencies for basic TCP Connect scanning

## Installation

1. Clone the repository or download the script:
   ```shell
   git clone https://github.com/yourusername/advanced-port-scanner.git
   cd advanced-port-scanner
   ```

2. Make the script executable:
   ```shell
   chmod +x port_scanner.py
   ```

3. For SYN and UDP scanning, install the Scapy library:
   ```shell
   # For Windows and macOS
   pip install scapy
   
   # For Linux
   pip3 install scapy
   
   # For Debian/Ubuntu systems
   sudo apt install python3-scapy
   ```

## Usage

```
./port_scanner.py [-h] [-t THREADS] [-T TIMEOUT] [-o OUTPUT] [-v] [-q] [-b] [-s] [-u]
                  [-V] [--json] [--config CONFIG] [--udp-retry UDP_RETRY] 
                  [--version-intensity VERSION_INTENSITY] [--rate RATE]
                  [--os-detection] [--os-detection-timeout OS_DETECTION_TIMEOUT]
                  [--ipv6] hosts ports
```

### Required Arguments

- `hosts`: Target host(s) to scan (hostname, IP address, or CIDR notation)
- `ports`: Port specification in one of these formats:
  - Single port: `80`
  - Port range: `20-25`
  - Comma-separated list: `22,80,443,8080`
  - All ports: `-`

### Options

- `-h, --help`: Show help message and exit
- `-t, --threads THREADS`: Number of threads to use (default: 50)
- `-T, --timeout TIMEOUT`: Timeout in seconds (default: 0.5)
- `-o, --output OUTPUT`: Output file for results
- `-v, --verbose`: Verbose output (shows ports as they're discovered)
- `-q, --quiet`: Suppress all output except results
- `-b, --banner`: Attempt to grab banners from open ports
- `-s, --syn`: Use SYN scanning (requires root/admin privileges)
- `-u, --udp`: Perform UDP scanning (requires root/admin privileges)
- `-V, --version-detection`: Perform service version detection
- `--json`: Output results in JSON format
- `--config CONFIG`: Path to custom port configuration file
- `--udp-retry UDP_RETRY`: Number of retries for UDP scanning (default: 3)
- `--version-intensity VERSION_INTENSITY`: Service version detection intensity (0-9, higher is more aggressive)
- `--rate RATE`: Rate limit: maximum packets per second (0 = no limit)
- `--os-detection`: Perform OS detection (requires root/admin privileges)
- `--os-detection-timeout OS_DETECTION_TIMEOUT`: Timeout for OS detection probes in seconds (default: 1.0)
- `--ipv6`: Force IPv6 scanning when possible

## Scanning Techniques

### TCP Connect Scan (Default)
- Completes the full TCP three-way handshake
- More detectable but works without special privileges
- Compatible with all systems and network configurations
- Works with both IPv4 and IPv6

### SYN Scan
- Only sends SYN packets without completing the handshake
- Stealthier and faster than TCP Connect scans
- Requires root/admin privileges and the Scapy library
- May be blocked by some firewalls
- Supports both IPv4 and IPv6

### UDP Scan
- Tests for open UDP ports by sending empty UDP packets
- Relies on ICMP "port unreachable" messages for closed ports
- Less reliable than TCP scanning due to the connectionless nature of UDP
- Requires root/admin privileges and the Scapy library
- Multiple retries are used to improve accuracy
- Supports both IPv4 and IPv6

## OS Detection

The port scanner includes a sophisticated OS fingerprinting module that:

- Uses TCP/IP stack behavior to identify operating systems
- Analyzes service banners for more accurate OS identification
- Combines multiple detection techniques for higher confidence results
- Can identify specific OS versions (e.g., Ubuntu 14.04, Windows Server 2019)
- Works with both IPv4 and IPv6 addresses
- Supports multiple probe types (SYN, ICMP, TCP NULL, TCP FIN)

## Service Version Detection

The scanner can identify specific service versions running on open ports:

- Uses advanced probing techniques to identify services
- Analyzes application-level responses for version information
- Configurable intensity levels for balance between accuracy and speed
- Supports common services like HTTP, FTP, SSH, SMTP, and more
- Works with both IPv4 and IPv6 services

## Examples

Scan a specific port:
```shell
./port_scanner.py example.com 80
```

Scan a range of ports with SYN scan (requires root):
```shell
sudo ./port_scanner.py 192.168.1.1 20-25 -s
```

Scan an IPv6 address:
```shell
./port_scanner.py 2001:db8::1 80,443 --ipv6
```

Scan multiple specific ports:
```shell
./port_scanner.py scanme.nmap.org 22,80,443
```

Scan all ports with 100 threads:
```shell
./port_scanner.py scanme.nmap.org - -t 100
```

Scan an entire subnet for SSH servers (works with IPv6 CIDR too):
```shell
./port_scanner.py 192.168.1.0/24 22
```

Scan with OS detection:
```shell
sudo ./port_scanner.py 10.0.0.1 20-100 --os-detection
```

Scan with banner grabbing and version detection:
```shell
./port_scanner.py 10.0.0.1 20-30 -b -V
```

Combined UDP and TCP scan with rate limiting:
```shell
sudo ./port_scanner.py 192.168.1.10 1-1000 -s -u --rate 100
```

Save scan results to a file in JSON format:
```shell
./port_scanner.py example.com 80-443 -o results --json
```

## Output Example

```

C8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DCbC8888DC8
dD|                     d8888b. .d8888.  .o88b.  .d8b.  d8b   db                     |Cb
d8|                     88  `8D 88'  YP d8P  Y8 d8   8b 888o  88                     |8b
d8|                     88oodD' `8bo.   8P      88   88 88V8o 88                     |8b
d8|                     88        `Y8b. 8b      88ooo88 88 V8o88                     |8b
d8|                     88      db   8D Y8b  d8 88   88 88  V888                     |8b
d8|                     88      `8888Y'  `Y88P' YP   YP VP   V8P                     |8D
C88DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888D


Starting SYN and UDP port scan on 1 host(s)
 - 192.168.1.1
Port range: 1-1000
Number of threads: 50
Timeout: 0.5 seconds

Progress: 2000/2000 ports scanned (100.0%) - Elapsed: 12.5s - ETA: 0.0s

Scan completed in 12.51 seconds
Scan type: SYN and UDP
Scanned 1 hosts and 2000 total ports
Total open ports found: 7 (TCP: 5, UDP: 2)

Target: 192.168.1.1
Open ports: 7 (TCP: 5, UDP: 2)
OS Detection: Ubuntu (Ubuntu 14.04) (Confidence: 95%)

TCP PORTS:
PORT     SERVICE        VERSION
------------------------------------------
22       SSH            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
53       DNS            
80       HTTP           Apache/2.4.7 (Ubuntu)
443      HTTPS          
8080     HTTP-ALT       HTTP/1.1 302 Found

UDP PORTS:
PORT     SERVICE        VERSION
--------------------
53       DNS            BIND 9.10.3
123      NTP            NTP v4
```

## Port Configuration

The scanner uses a port configuration file in JSON format to identify services. A default configuration is included, but you can customize it:

```json
{
  "common_ports": {
    "20": "FTP-DATA",
    "21": "FTP",
    "22": "SSH",
    "23": "TELNET",
    "25": "SMTP",
    "53": "DNS",
    "80": "HTTP",
    "110": "POP3",
    "143": "IMAP",
    "443": "HTTPS",
    "3306": "MySQL",
    "3389": "RDP"
  }
}
```

Place this file in the same directory as the script or specify a custom path with the `--config` option.

## Performance Optimization

- SYN scanning is generally faster than TCP Connect scanning
- UDP scanning is slower and less reliable than TCP-based methods
- Increasing thread count improves speed but consumes more system resources
- Reducing timeout values speeds up scans but may increase false negatives
- For large networks or wide port ranges, consider scanning in smaller batches
- Use rate limiting (`--rate`) to avoid overwhelming targets or triggering IDS alerts

## Advanced Features

### Module Structure

- **port_scanner.py**: Main scanning engine with TCP/UDP scanning capabilities
- **os_fingerprinter.py**: OS detection module that uses TCP/IP stack behavior and service banners
- **service_prober.py**: Advanced service detection for identifying specific versions

### IPv6 Support

All scanning methods (TCP Connect, SYN, UDP) fully support IPv6 addresses:

- Scans IPv6-only hosts
- Handles dual-stack hosts (IPv4 and IPv6)
- Supports IPv6 CIDR notation for network scans
- Automatically detects address family and uses appropriate methods

### Banner Analysis

The scanner performs intelligent banner analysis:

- Interprets protocol-specific responses (HTTP, FTP, SSH, etc.)
- Extracts vendor and version information
- Uses banner information to help identify the operating system
- Caches results to avoid redundant probes

## Limitations

- SYN and UDP scanning require root/administrator privileges and the Scapy library
- Banner grabbing may not work with all services or protocols
- UDP scanning has inherent reliability issues due to the protocol's design
- OS fingerprinting accuracy varies depending on target configuration and available services

## Legal Disclaimer

*This tool is provided for educational and legitimate network administration purposes only. Unauthorized port scanning may violate the terms of service of networks or service providers. Always ensure you have permission to scan the target systems.*

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Roadmap

- [x] Banner Grabbing
- [x] SYN Scanning
- [x] JSON Format Output
- [x] UDP Scanning
- [x] Service Version Detection
- [x] IPv6 Support
- [x] OS Fingerprinting
- [ ] Enhanced Reliability for UDP Scanning
- [ ] Script-Based Service Enumeration
- [ ] Vulnerability Detection
- [ ] Adaptive Scan Techniques