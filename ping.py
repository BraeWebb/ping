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
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW)
        sock.sendto(packet, (dest, 1))
        yield sock
        sock.close()
    except socket.error as error:
        print(error)
        log_error(Errors.SOCKET_ERROR, dest)


class Packet(object):

    _version = 4
    _header_length = 5
    _service_type = 0
    _flags = 0
    _frag_off = 0

    def __init__(self, from_ip, to_ip, ttl=60):
        self.length = 0
        self.ttl = ttl
        self.id = 2405
        self.protocol = socket.IPPROTO_NONE
        self.checksum = 0
        self.from_ip = socket.inet_aton(from_ip)
        self.to_ip = socket.inet_aton(to_ip)

    @property
    def ip_header(self):
        return pack('!BBBHHHBBH4s4s', self._version, self._header_length,
                    self._service_type, self.length, self.id, self._frag_off,
                    self.ttl, self.protocol, self.checksum, self.from_ip,
                    self.to_ip)


# tcp header fields
tcp_source = 1234   # source port
tcp_dest = 80   # destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons(5840)    #   maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)


class TCPPacket(Packet):

    def __init__(self, source, dest, ttl=60):
        from_ip, self.from_port = source
        to_ip, self.to_port = dest

        super().__init__(from_ip, to_ip, ttl=ttl)

        self.protocol = socket.IPPROTO_TCP
        self.sequence = 0
        self.ack_sequence = 0
        self.offset = 5

    @property
    def tcp_header(self):
        return pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                    tcp_offset_res, tcp_flags,  tcp_window, tcp_check,
                    tcp_urg_ptr)


class ICMPPacket(object):
    def __init__(self, type_=8, code=0):
        self._type = type_
        self._code = code
        self._checksum = 0

    @property
    def ping_header(self):
        return pack('!bbHHh', self._type, self._code, self._checksum, 0, 0)

def main():
    """Main programmy thing, y'all know what it do"""
    parser = argparse.ArgumentParser(description="Ping Tool")

    parser.add_argument("hostname", type=str, action="store",
                        help="the hostname to lookup")

    args = parser.parse_args()

    ip = socket.gethostbyname(args.hostname)

    source_ip = '10.0.0.42'
    dest_ip = ip # or socket.gethostbyname('www.google.com')


    # ip header fields
    # ip_ihl = 5
    # ip_ver = 4
    # ip_tos = 0
    # ip_tot_len = 0  # kernel will fill the correct total length
    # ip_id = 54321   #Id of this packet
    # ip_frag_off = 0
    # ip_ttl = 255
    # ip_proto = socket.IPPROTO_TCP
    # ip_check = 0    # kernel will fill the correct checksum
    # ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
    # ip_daddr = socket.inet_aton ( dest_ip )
    #
    # # ip_ihl_ver = (ip_ver << 4) + ip_ihl
    #
    # # the ! in the pack format string means network order
    # ip_header = pack('!BBBHHHBBH4s4s' , ip_ver, ip_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # ip_header = Packet(source_ip, dest_ip, ttl=60).ip_header

    # with send_packet(ip, ip_header) as sock:
    #     pass

    packet = Packet("127.0.0.1", ip)
    tcp_packet = ICMPPacket()
    # print(tcp_packet.ping_header)

    with send_packet(ip, tcp_packet.ping_header) as sock:
        print(sock)
        print(sock.recv(1024))
    # send_packet(ip, packet.ip_header + tcp_packet.ping_header)

    print(ip)


if __name__ == "__main__":
    main()
