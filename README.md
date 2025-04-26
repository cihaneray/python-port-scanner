# Advanced TCP Port Scanner
[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.6+](https://img.shields.io/badge/Python-3.6+-blueviolet.svg)](https://www.python.org/downloads/)
[![Maintenance: Active](https://img.shields.io/badge/Maintenance-Active-success.svg)](https://github.com/cihaneray/Python-PortScanner)
[![OS](https://img.shields.io/badge/OS-Linux%20%7C%20WindowsOS-orange.svg)]()

A fast, multithreaded TCP port scanner written in Python that allows you to scan for open ports on target hosts, supporting individual hosts, IP addresses, and CIDR notation with both TCP Connect and SYN scanning methods.

## Features

- Multiple scanning techniques: TCP Connect and SYN scanning
- Scan individual hosts, IPs, or entire subnets using CIDR notation
- Scan single ports, port ranges, comma-separated port lists, or all ports
- Multithreaded scanning for improved performance
- Service identification for common ports
- Banner grabbing to identify services running on open ports
- Progress reporting with estimated time remaining
- Result saving to output files
- Configurable timeout settings
- Verbose and quiet modes for different output levels
- Customizable port service definitions via external configuration

## Requirements

- Python 3.6 or higher
- For SYN scanning:
  - Root/Administrator privileges
  - Scapy library
- No external dependencies for basic TCP Connect scanning

## Installation

1. Download the script and make it executable:
   ```shell
   chmod +x port_scanner.py
   ```

2. For SYN scanning, install the Scapy library:
   ```shell
   pip install scapy # For Windows
   pip3 install scapy # For Linux
   sudo apt install python3-scapy # If you are using Debian or Ubuntu based distros
   ```

## Usage

```
./port_scanner.py [-h] [-t THREADS] [-T TIMEOUT] [-o OUTPUT] [-v] [-q] [-b] [-s] [--config CONFIG] hosts ports
```

### Arguments

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
- `-v, --verbose`: Verbose output
- `-q, --quiet`: Suppress all output except results
- `-b, --banner`: Attempt to grab banners from open ports
- `-s, --syn`: Use SYN scanning (requires root/admin privileges and scapy)
- `--config CONFIG`: Path to custom port configuration file

## Scanning Techniques

### TCP Connect Scan (Default)
- Completes the full TCP three-way handshake
- Easier to detect but works without special privileges
- Compatible with all systems and network setups

### SYN Scan
- Only sends SYN packets without completing the handshake
- Stealthier and faster than TCP Connect scans
- Requires root/admin privileges and the Scapy library
- May be blocked by some firewalls

## Examples

Scan a specific port:
```shell
./port_scanner.py example.com 80
```

Scan a range of ports with SYN scan (requires root):
```shell
sudo ./port_scanner.py 192.168.1.1 20-25 -s
```

Scan specific ports:
```shell
./port_scanner.py scanme.nmap.org 22,80,443
```

Scan all ports with 100 threads:
```shell
./port_scanner.py scanme.nmap.org - -t 100
```

Scan an entire subnet:
```shell
./port_scanner.py 192.168.1.0/24 22
```

Scan with banner grabbing:
```shell
./port_scanner.py 10.0.0.1 20-30 -b
```

Scan with SYN technique and banner grabbing:
```shell
sudo ./port_scanner.py 192.168.1.10 1-1000 -s -b
```

## Output Example

```
Starting SYN port scan on 1 host(s)
 - example.com (93.184.216.34)
Port range: 80-443
Number of threads: 50
Timeout: 0.5 seconds

Progress: 364/364 ports scanned (100.0%) - Elapsed: 5.2s - ETA: 0.0s

Scan completed in 5.23 seconds
Scan type: SYN
Scanned 1 hosts and 364 total ports
Total open ports found: 2

Target: 93.184.216.34
Open ports: 2
PORT     SERVICE
-----------------
80       HTTP
443      HTTPS

Results saved to scan_results.txt
```

## Port Configuration

The scanner can use a custom port configuration file in JSON format:

```json
{
  "common_ports": {
    "20": "FTP-DATA",
    "21": "FTP",
    "22": "SSH",
    "80": "HTTP",
    "443": "HTTPS"
  }
}
```

Place this file in the same directory as the script or specify a custom path with the `--config` option.

## Performance Notes

- SYN scanning is generally faster than TCP Connect scanning
- Increasing the number of threads can improve scanning speed but may impact system performance
- Decreasing the timeout value can speed up scans but may increase the chance of missing slower responding ports
- Scanning large port ranges or subnets can take significant time, especially with higher timeout values

## Limitations

- SYN scanning requires root/administrator privileges and the Scapy library
- Banner grabbing may not work with all services
- No OS fingerprinting capabilities

## Legal Disclaimer

This tool is provided for educational and legitimate network administration purposes only. Unauthorized port scanning may be against the terms of service of some networks or services. Always ensure you have permission to scan the target systems.

## License

This project is open-source software. Feel free to use, modify, and distribute as needed.

## Todos

- [X] ~~Banner Grabbing~~
- [X] ~~SYN Scanning~~
- [ ] UDP Scanning
