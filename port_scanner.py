#!/usr/bin/python3

import sys
import time
import socket
import threading

from typing import List
from queue import Queue, Empty
from argparse import ArgumentParser, Namespace


class PortScanner:
    def __init__(self) -> None:
        self.queue: Queue = Queue()
        self.open_ports: List[int] = []
        self.lock = threading.Lock()
        self.total_ports = 0
        self.scanned_ports = 0
        self.start_time = 0
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT"
        }
        self.args = self.parse_arguments()
        self.scan()

    @staticmethod
    def parse_arguments() -> Namespace:
        parser = ArgumentParser(description='Advanced TCP Port Scanner')
        parser.add_argument('host', help='Host to scan')
        parser.add_argument('ports', help='Port range to scan, formatted as start-end or "-" for all ports')
        parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads to use (default: 50)')
        parser.add_argument('-T', '--timeout', type=float, default=0.5, help='Timeout in seconds (default: 0.5)')
        parser.add_argument('-o', '--output', help='Output file for results')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all output except results')

        return parser.parse_args()

    def scan(self) -> None:
        # Parse port range
        if self.args.ports == '-':
            start_port, end_port = 1, 65535
        else:
            try:
                if '-' in self.args.ports:
                    start_port, end_port = map(int, self.args.ports.split('-'))
                else:
                    start_port = end_port = int(self.args.ports)

                if not 1 <= start_port <= 65535 or not 1 <= end_port <= 65535:
                    print("Error: Port numbers must be between 1 and 65535")
                    sys.exit(1)
            except ValueError:
                print("Error: Invalid port range format. Use start-end or a single port number.")
                sys.exit(1)

        # Resolve target hostname
        try:
            target_ip = socket.gethostbyname(self.args.host)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {self.args.host}")
            sys.exit(1)

        # Print scan information
        if not self.args.quiet:
            print(f"\nStarting port scan on host {self.args.host} ({target_ip})")
            print(f"Port range: {start_port}-{end_port}")
            print(f"Number of threads: {self.args.threads}")
            print(f"Timeout: {self.args.timeout} seconds\n")

        # Initialize scan variables
        self.total_ports = end_port - start_port + 1
        self.scanned_ports = 0
        self.start_time = time.time()

        # Fill the queue with ports to scan
        for port in range(start_port, end_port + 1):
            self.queue.put(port)

        # Start worker threads
        threads = []
        for _ in range(min(self.args.threads, self.total_ports)):
            t = threading.Thread(target=self.worker, args=(target_ip,))
            t.daemon = True
            threads.append(t)
            t.start()

        # Print progress while waiting for scan to complete
        if not self.args.quiet:
            self.print_progress()

        # Wait for all ports to be scanned
        self.queue.join()

        # Display results
        self.print_results(target_ip)

        # Save results if requested
        if self.args.output:
            self.save_results(target_ip)

    def tcp_test(self, port: int, target_ip: str) -> bool:
        """Test if a port is open."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.args.timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                return True
        return False

    def worker(self, target_ip: str) -> None:
        """Worker thread to scan ports."""
        while True:
            try:
                port = self.queue.get(block=False)
            except Empty:
                break

            try:
                self.tcp_test(port, target_ip)
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

            sys.stdout.write(f"\rProgress: {self.scanned_ports}/{self.total_ports} ports scanned "
                             f"({progress:.1f}%) - Elapsed time: {elapsed:.1f}s")
            sys.stdout.flush()
            time.sleep(0.5)

        # Final progress update
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def get_service_name(self, port: int) -> str:
        """Return service name for well-known ports."""
        return self.common_ports.get(port, "Unknown")

    def print_results(self, target_ip: str) -> None:
        """Display scan results."""
        self.open_ports.sort()

        elapsed = time.time() - self.start_time

        print(f"\nScan completed in {elapsed:.2f} seconds")
        print(f"Target: {self.args.host} ({target_ip})")
        print(f"Open ports: {len(self.open_ports)}/{self.total_ports}\n")

        if self.open_ports:
            print("PORT     SERVICE")
            print("-----------------")
            for port in self.open_ports:
                service = self.get_service_name(port)
                print(f"{port:<8} {service}")
        else:
            print("No open ports found.")

    def save_results(self, target_ip: str) -> None:
        """Save scan results to a file."""
        try:
            with open(self.args.output, 'w') as f:
                f.write(f"Port scan results for {self.args.host} ({target_ip})\n")
                f.write(f"Scan date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Open ports: {len(self.open_ports)}/{self.total_ports}\n\n")

                if self.open_ports:
                    f.write("PORT     SERVICE\n")
                    f.write("-----------------\n")
                    for port in self.open_ports:
                        service = self.get_service_name(port)
                        f.write(f"{port:<8} {service}\n")
                else:
                    f.write("No open ports found.\n")

            print(f"\nResults saved to {self.args.output}")
        except IOError as e:
            print(f"Error saving results: {e}")


if __name__ == '__main__':
    try:
        PortScanner()
    except KeyboardInterrupt:
        print("\nScan aborted by user")
        sys.exit(0)
