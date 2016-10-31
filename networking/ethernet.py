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

    def __repr__(self):
        return 'Ethernet Frame:\n' + \
               TAB_1 + 'Destination: {}, Source: {}, Protocol: {}\n'\
                       .format(self.dest_mac, self.src_mac, self.proto)
