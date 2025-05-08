# Advanced Port Scanner
[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.6+](https://img.shields.io/badge/Python-3.6+-blueviolet.svg)](https://www.python.org/downloads/)
[![Maintenance: Active](https://img.shields.io/badge/Maintenance-Active-success.svg)](https://github.com/yourusername/advanced-port-scanner)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20macOS-orange.svg)]()

A versatile, **multithreaded** port scanner written in **Python** that supports **TCP** Connect, **SYN**, and **UDP** scanning methods. This tool allows you to scan for open ports on target hosts, with support for individual hosts, IP addresses, and **CIDR** notation.
```
       C8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DCb
      dD                d8888b. .d8888.  .o88b.  .d8b.  d8b   db                Cb
     d8'                88  `8D 88'  YP d8P  Y8 d8' `8b 888o  88                `8b
    d8'                 88oodD' `8bo.   8P      88ooo88 88V8o 88                 `8b
   d8'                  88~~~     `Y8b. 8b      88~~~88 88 V8o88                  `8b
  d8'                   88      db   8D Y8b  d8 88   88 88  V888                   `8b
 C8'                    88      `8888Y'  `Y88P' YP   YP VP   V8P                    `8D
C88DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888DC8888D
```

## Features

- **Multiple scanning techniques**: TCP Connect, SYN, and UDP scanning
- **Flexible target specification**: Scan individual hosts, IPs, or entire subnets using CIDR notation
- **Versatile port selection**: Scan single ports, port ranges, comma-separated port lists, or all ports
- **Performance optimized**: Multithreaded scanning for improved speed
- **Service identification**: Automatic detection of common services on open ports
- **Banner grabbing**: Identify specific service versions running on open ports
- **Real-time feedback**: Progress reporting with estimated time remaining
- **Output options**: Save results as plain text or JSON format
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
                  [--json] [--config CONFIG] [--udp-retry UDP_RETRY] hosts ports
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
- `--json`: Output results in JSON format
- `--config CONFIG`: Path to custom port configuration file
- `--udp-retry UDP_RETRY`: Number of retries for UDP scanning (default: 3)

## Scanning Techniques

### TCP Connect Scan (Default)
- Completes the full TCP three-way handshake
- More detectable but works without special privileges
- Compatible with all systems and network configurations

### SYN Scan
- Only sends SYN packets without completing the handshake
- Stealthier and faster than TCP Connect scans
- Requires root/admin privileges and the Scapy library
- May be blocked by some firewalls

### UDP Scan
- Tests for open UDP ports by sending empty UDP packets
- Relies on ICMP "port unreachable" messages for closed ports
- Less reliable than TCP scanning due to the connectionless nature of UDP
- Requires root/admin privileges and the Scapy library
- Multiple retries are used to improve accuracy

## Examples

Scan a specific port:
```shell
./port_scanner.py example.com 80
```

Scan a range of ports with SYN scan (requires root):
```shell
sudo ./port_scanner.py 192.168.1.1 20-25 -s
```

Scan multiple specific ports:
```shell
./port_scanner.py scanme.nmap.org 22,80,443
```

Scan all ports with 100 threads:
```shell
./port_scanner.py scanme.nmap.org - -t 100
```

Scan an entire subnet for SSH servers:
```shell
./port_scanner.py 192.168.1.0/24 22
```

Scan with banner grabbing:
```shell
./port_scanner.py 10.0.0.1 20-30 -b
```

Combined UDP and TCP scan with banner grabbing:
```shell
sudo ./port_scanner.py 192.168.1.10 1-1000 -s -u -b
```

Save scan results to a file in JSON format:
```shell
./port_scanner.py example.com 80-443 -o results --json
```

## Output Example

```
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

TCP PORTS:
PORT     SERVICE        BANNER
------------------------------------------
22       SSH            SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
53       DNS            
80       HTTP           HTTP/1.1 200 OK
443      HTTPS          
8080     HTTP-ALT       HTTP/1.1 302 Found

UDP PORTS:
PORT     SERVICE
--------------------
53       DNS
123      NTP
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

## Limitations

- SYN and UDP scanning require root/administrator privileges and the Scapy library
- Banner grabbing may not work with all services or protocols
- UDP scanning has inherent reliability issues due to the protocol's design
- The scanner does not perform OS fingerprinting or vulnerability detection
- Limited IPv6 support

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
- [ ] IPv6 Support
- [ ] OS Fingerprinting
- [ ] Enhanced Reliability for UDP Scanning
- [ ] Vulnerability Detection
- [ ] (Uncertain) ML Based OS Fingerprinting
