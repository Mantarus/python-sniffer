import socket
import struct
from general import *


class Ethernet:

    def __init__(self, raw_data):
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]

    def print_header(self, prefix):
        print(prefix + '\nEthernet Frame:')
        print(prefix + TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.
              format(self.dest_mac, self.src_mac, self.proto))
