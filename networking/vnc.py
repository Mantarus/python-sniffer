class VNC:
    ports = range(5900, 5907)
    
    def __init__(self, raw_data):
        self.data = raw_data
    
    def __repr__(self):
        return self.data


class VNCProtocolVersion(VNC):

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.data = raw_data.decode('utf-8')

    def __repr__(self):
        return 'VNC Packet:\n' + \
              'VNC Protocol Version: {}\n'.format(self.data)
