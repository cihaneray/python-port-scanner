# Advanced TCP Port Scanner

A fast, multithreaded TCP port scanner written in Python that allows you to scan for open ports on target hosts.

## Features

- Scan single ports or port ranges
- Multithreaded scanning for improved performance
- Service identification for common ports
- Progress reporting during scanning
- Result saving to output files
- Configurable timeout settings
- Verbose and quiet modes for different output levels

## Requirements

- Python 3.6 or higher
- Standard Python libraries (no external dependencies)

## Installation

No installation is required. Simply download the script and make it executable:

```bash
chmod +x port_scanner.py
```

## Usage

```
./port_scanner.py [-h] [-t THREADS] [-T TIMEOUT] [-o OUTPUT] [-v] [-q] host ports
```

### Arguments

- `host`: Target host to scan (hostname or IP address)
- `ports`: Port range to scan (formatted as start-end or a single port)
  - Use `-` to scan all ports (1-65535)

### Options

- `-h, --help`: Show help message and exit
- `-t, --threads THREADS`: Number of threads to use (default: 50)
- `-T, --timeout TIMEOUT`: Timeout in seconds (default: 0.5)
- `-o, --output OUTPUT`: Output file for results
- `-v, --verbose`: Verbose output
- `-q, --quiet`: Suppress all output except results

## Examples

Scan a specific port:
```bash
./port_scanner.py example.com 80
```

Scan a range of ports:
```bash
./port_scanner.py 192.168.1.1 20-25
```

Scan all ports with 100 threads:
```bash
./port_scanner.py scanme.nmap.org - -t 100
```

Scan with a custom timeout and save results:
```bash
./port_scanner.py localhost 1-1000 -T 1.0 -o results.txt
```

Run a quiet scan:
```bash
./port_scanner.py 10.0.0.1 1-100 -q
```

## Output Example

```
Starting port scan on host example.com (93.184.216.34)
Port range: 80-443
Number of threads: 50
Timeout: 0.5 seconds

Progress: 364/364 ports scanned (100.0%) - Elapsed time: 5.2s

Scan completed in 5.23 seconds
Target: example.com (93.184.216.34)
Open ports: 2/364

PORT     SERVICE
-----------------
80       HTTP
443      HTTPS

Results saved to scan_results.txt
```

## Performance Notes

- Increasing the number of threads can improve scanning speed but may impact system performance
- Decreasing the timeout value can speed up scans but may increase the chance of missing slower responding ports
- Scanning large port ranges can take significant time, especially with higher timeout values

## Limitations

- Only performs TCP connect scans (no UDP, SYN scanning, etc.)
- Limited service identification (only identifies common services)
- No OS fingerprinting capabilities

## Legal Disclaimer

This tool is provided for educational and legitimate network administration purposes only. Unauthorized port scanning may be against the terms of service of some networks or services. Always ensure you have permission to scan the target systems.

## License

This project is open-source software. Feel free to use, modify, and distribute as needed.
