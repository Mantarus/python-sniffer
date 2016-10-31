import struct


class VNC:
    header = 'VNC Packet:\n'
    ports = range(5900, 5907)

    def __init__(self, raw_data):
        self.version = raw_data

    def __repr__(self):
        return VNC.header


class VNCProtocolVersion(VNC):
    header = 'VNC Protocol Version Packet:\n'

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.version = raw_data.decode('utf-8')

    def __repr__(self):
        return super().__repr__() + \
               VNCProtocolVersion.header + \
               'VNC Protocol Version: {}\n'.format(self.version)


class VNCClientMessage(VNC):
    header = 'VNC Client Message Packet:\n'

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.message_code = struct.unpack('! B', raw_data[:1])[0]

    def __repr__(self):
        return super().__repr__() + \
               VNCClientMessage.header + \
               'Message code: {}\n'.format(self.message_code)


class VNCFrameBufferUpdateMessage(VNCClientMessage):
    header = 'VNC Framebuffer Update Message Packet:\n'

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.rect_num, self.x_pos, self.y_pos, self.width, self.height, self.encoding = \
            struct.unpack('! x H H H H H l', raw_data[1:16])

    def __repr__(self):
        return super().__repr__() + VNCFrameBufferUpdateMessage.header + \
               'Number of rectangles: {}\n'.format(self.rect_num) + \
               'X Pos: {} Y Pos: {}\n'.format(self.x_pos, self.y_pos) + \
               'Width: {} Height: {}\n'.format(self.width, self.height) + \
               'Encoding type: {}\n'.format(self.encoding)


class VNCFrameBufferUpdateRequestMessage(VNCClientMessage):
    header = 'VNC Framebuffer Update Request Message Packet:\n'

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.incr, self.x_pos, self.y_pos, self.width, self.height = \
            struct.unpack('! B H H H H', raw_data[1:])

    def __repr__(self):
        return super().__repr__() + VNCFrameBufferUpdateRequestMessage.header + \
               'Incremental: {}\n'.format(self.incr) + \
               'X Pos: {} Y Pos: {}\n'.format(self.x_pos, self.y_pos) + \
               'Width: {} Height: {}\n'.format(self.width, self.height)


class VNCKeyEventMessage(VNCClientMessage):
    header = 'VNC Key Event Message:\n'

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.down_flag, self.key = struct.unpack('! B 2x I', raw_data[1:])

    def __repr__(self):
        return super().__repr__() + VNCKeyEventMessage.header + \
               'Down flag: {} Key hex code: {}\n'.format(bool(self.down_flag), hex(self.key))


class VNCPointerEventMessage(VNCClientMessage):
    header = 'VNC Pointer Event Message:\n'

    def __init__(self, raw_data):
        super().__init__(raw_data)
        self.button, self.x_pos, self.y_pos = struct.unpack('! B H H', raw_data[1:6])

    def __repr__(self):
        return super().__repr__() + VNCPointerEventMessage.header + \
               'Button code: {}\n'.format(self.button) + \
               'X Pos: {} Y Pos: {}\n'.format(self.x_pos, self.y_pos)
