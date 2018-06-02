#!/usr/local/bin/python3

import argparse
import sys
import socket
from enum import Enum
import random
import time

from struct import pack


PING_COUNT = 2
TIMEOUT = 1
MAX_HOPS = 50


class Errors(Enum):
    """An Enum representing the types of errors that may occur."""
    SOCKET_ERROR = "Unable to open TCP socket connection to {}"
    HOSTNAME_ERROR = "Not a valid hostname"
    UNREACHABLE = "Request timed out"


def log_error(error, *parameters):
    """
    Log that an error has occurred and exit the program.
    Args:
        error (Errors): The type of error that has occurred.
        *parameters (*): Any extra information relevant to the error.
    """
    print(error.value.format(*parameters))
    sys.exit(1)


class Sender:
    def __init__(self, destination, packet, ttl=-1, timeout=TIMEOUT):
        self.destination = destination
        self.packet = packet
        self.ttl = ttl
        self._timeout = timeout
        self.timeout = False

    def __call__(self, size=1024, data=False, sender=True):
        reply, (ip, port) = self.socket.recvfrom(size)
        if data and sender:
            return reply, ip
        if data:
            return reply
        if sender:
            return ip

    def __enter__(self):
        self.socket = sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                           socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        sock.settimeout(self._timeout)
        sock.sendto(self.packet, (self.destination, 1))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type == socket.timeout:
            self.timeout = True
            return True
        self.socket.close()


def checksum(destination):
    total = 0
    count_to = (len(destination) // 2) * 2

    for count in range(0, count_to, 2):
        total += better_ord(destination[count + 1]) * 256 + better_ord(destination[count])

    if count_to < len(destination):
        total = total + better_ord(destination[len(destination) - 1])

    total = (total >> 16) + (total & 0xffff)
    total = total + (total >> 16)
    answer = ~total
    answer = answer & 0xffff
    return answer


def better_ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)


class Clock:
    def __enter__(self):
        self.start = time.time()
        self.end = 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.time()

    @property
    def duration(self):
        if self.end:
            return (self.end - self.start) * 1000
        return (time.time() - self.start) * 1000


class ICMPPacket(object):
    def __init__(self, hostname, timeout=TIMEOUT):
        self._hostname = hostname
        self.timeout = timeout
        self._type = 8
        self._code = 0
        self._checksum = 0
        self._id = random.randint(0, 65565)
        self._seq = 0

    def build_header(self):
        return pack('BBHHH', self._type, self._code,
                    self._checksum, self._id, self._seq)

    @property
    def address(self):
        try:
            return socket.gethostbyname(self._hostname)
        except socket.gaierror:
            log_error(Errors.HOSTNAME_ERROR, self._hostname)
            return None

    @property
    def header(self):
        self._seq += 1
        self._checksum = 0
        dummy = self.build_header()
        self._checksum = checksum(dummy)
        return self.build_header()


def time_ping(packet, times=PING_COUNT):
    for i in range(times):
        with Sender(packet.address, packet.header,
                    timeout=packet.timeout) as sender:
            with Clock() as clock:
                sender()
            yield clock.duration
        if sender.timeout:
            yield False


def trace_route(packet, max_hops=MAX_HOPS):
    address = packet.address
    for i in range(1, max_hops):
        with Sender(address, packet.header,
                    ttl=i, timeout=packet.timeout) as sender:
            with Clock() as clock:
                hop = sender()
                yield hop, clock.duration
            if hop == address:
                break
        if sender.timeout:
            yield "*", clock.duration


def main():
    """Main programmy thing, y'all know what it do"""
    parser = argparse.ArgumentParser(description="Ping Tool")

    parser.add_argument("hostname", type=str, action="store",
                        help="the hostname to lookup")

    parser.add_argument("--pings", type=int, action="store", default=PING_COUNT,
                        help="amount of pings to send to average")
    parser.add_argument("--trace", action="store_true",
                        help="display a trace route to the destination")
    parser.add_argument("--timeout", type=int, action="store", default=TIMEOUT,
                        help="specify the duration before timing out")
    parser.add_argument("--max-hops", type=int, action="store", default=MAX_HOPS,
                        help="maximum number of hops to reach a destination")

    args = parser.parse_args()

    print("Pyping by B.Webb")
    print()

    packet = ICMPPacket(args.hostname, timeout=args.timeout)

    print(f"Sending {args.pings + 1} PINGs to {args.hostname}, IP {packet.address}")

    delays = time_ping(packet, times=args.pings)
    delays = [delay for delay in delays if delay]

    if not delays:
        log_error(Errors.UNREACHABLE)

    hops, hop = None, None
    for hops, hop in enumerate(trace_route(packet, max_hops=args.max_hops)):
        if args.trace:
            print("{} {} {:.3f}ms".format(hops+1, *hop))

    if hop:
        delays.append(hop[1])

    average = sum(delays) / len(delays)

    print(f"{len(delays)} replies received with average {average:.0f} ms, {hops+1} hops.")


if __name__ == "__main__":
    main()
