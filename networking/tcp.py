import struct

from general import *


class TCP:

    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]

    def __repr__(self):
        return 'TCP Segment:\n' + \
               'Source Port: {}, Destination Port: {}\n'.format(self.src_port, self.dest_port) + \
               TAB_1 + 'Sequence: {}, Acknowledgment: {}\n'.format(self.sequence, self.acknowledgment) + \
               TAB_1 + 'Flags:\n' + \
               TAB_2 + 'URG: {}, ACK: {}, PSH: {}\n'.format(self.flag_urg, self.flag_ack, self.flag_psh) + \
               TAB_2 + 'RST: {}, SYN: {}, FIN:{}\n'.format(self.flag_rst, self.flag_syn, self.flag_fin)