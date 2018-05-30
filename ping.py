#!/usr/local/bin/python3

import argparse
import sys
import socket
from contextlib import contextmanager
from enum import Enum
import random

from struct import *


class Errors(Enum):
    """An Enum representing the types of errors that may occur."""
    SOCKET_ERROR = "Unable to open TCP socket connection to {}"
    HOSTNAME_ERROR = "Hostname ({}) could not be resolved."


def log_error(error, *parameters):
    """
    Log that an error has occurred and exit the program.
    Args:
        error (Errors): The type of error that has occurred.
        *parameters (*): Any extra information relevant to the error.
    """
    print(error.name, ":", error.value.format(*parameters))
    sys.exit(1)


@contextmanager
def send_packet(dest, packet):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        sock.sendto(packet, (dest, 1))
        yield sock
        sock.close()
    except socket.error as error:
        print(error)
        log_error(Errors.SOCKET_ERROR, dest)


def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = better_ord(source_string[count + 1])*256+better_ord(source_string[count])
        sum = sum + this_val
        count = count + 2
    if count_to < len(source_string):
        sum = sum + better_ord(source_string[len(source_string) - 1])
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    return answer

def better_ord(value):
    if type(value) == int:
        return value
    else:
        return ord(value)


class ICMPPacket(object):
    def __init__(self, type_=8, code=0):
        self._type = type_
        self._code = code
        self._checksum = 0
        self._id = random.randint(0, 65565)
        self._seq = 0

    def build_header(self):
        return pack('BBHHH', self._type, self._code,
                    self._checksum, self._id, self._seq)

    @property
    def header(self):
        self._seq += 1
        self._checksum = 0
        dummy = self.build_header()
        self._checksum = checksum(dummy)
        return self.build_header()


def main():
    """Main programmy thing, y'all know what it do"""
    parser = argparse.ArgumentParser(description="Ping Tool")

    parser.add_argument("hostname", type=str, action="store",
                        help="the hostname to lookup")

    args = parser.parse_args()

    ip = socket.gethostbyname(args.hostname)

    packet = ICMPPacket()

    with send_packet(ip, packet.header) as sock:
        print(sock.recv(1024))

    print(ip)


if __name__ == "__main__":
    main()
