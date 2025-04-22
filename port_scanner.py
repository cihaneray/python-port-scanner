#! /usr/bin/python3

import threading

from queue import Queue
from argparse import ArgumentParser, Namespace
from socket import AF_INET, SOCK_STREAM, gethostbyname, socket


class PortScanner:
    def __init__(self) -> None:
        self.queue: Queue = Queue()
        self.set_parser()

    def set_parser(self) -> None:
        parser: ArgumentParser = ArgumentParser(description='TCP Port Scanner')
        parser.add_argument('host', help='Host to scan')
        parser.add_argument('ports', help='Port range to scan, formatted as start-end')
        args: Namespace = parser.parse_args()
        if args.ports == '-':
            start_port, end_port = 1, 65535
        else:
            start_port, end_port = map(int, args.ports.split('-'))
        self.main(args.host, start_port, end_port)

    @staticmethod
    def tcp_test(port: int, target_ip: str) -> None:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            result: int = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"Opened Port: {port}")

    def worker(self, target_ip: str, queue: Queue) -> None:
        while not queue.empty():
            port = queue.get()
            self.tcp_test(port, target_ip)
            queue.task_done()

    def main(self, host: str, start_port: int, end_port: int) -> None:
        target_ip = gethostbyname(host)
        for port in range(start_port, end_port + 1):
            self.queue.put(port)
        for _ in range(100):
            t = threading.Thread(target=self.worker, args=(target_ip, self.queue,))
            t.daemon = True
            t.start()
        self.queue.join()
        print("Scanning completed.")


if __name__ == '__main__':
    PortScanner()
