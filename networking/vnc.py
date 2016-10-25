import struct

from general import *


class VNC:
    
    def __init__(self, raw_data):
        self.data = raw_data
    
    def print(self, prefix):
        print(prefix + self.data)


class VNCProtocolVersion(VNC):

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.data = raw_data.decode('utf-8')

    def print(self, prefix):
        print(prefix + 'VNC Packet:')
        print(prefix + 'VNC Protocol Version: {}'.format(self.data))