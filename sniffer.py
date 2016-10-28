import socket
import sys
import itertools
import struct
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.tcp import TCP
from networking.vnc import *


def main():

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' + str(msg.errno) + ' Message ' + msg.strerror)
        sys.exit()

    for cnt in itertools.count():
        raw_data, addr = conn.recvfrom(65565)
        packet = []
        print('Receive packet #{} at {}'.format(str(cnt), str(addr[0])))
        eth = Ethernet(raw_data)
        packet.append(eth)

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            packet.append(ipv4)

            # TCP
            if ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                packet.append(tcp)

                if tcp.dest_port in VNC.ports or tcp.src_port in VNC.ports:
                    print('Probably VNC Packet!')
                    print('SRC IP: {} DST IP {}\nSRC PORT: {} DEST PORT: {}'\
                          .format(ipv4.src, ipv4.target, tcp.src_port, tcp.dest_port))

                mapped = False

                if not mapped:
                    try:
                        tcp.data.decode('utf-8')
                    except:
                        pass
                    else:
                        if len(tcp.data) == 12 and tcp.data.decode('utf-8')[:3] == 'RFB':
                            vnc = VNCProtocolVersion(tcp.data)
                            packet.append(vnc)
                            for item in packet:
                                print(item)
                            mapped = True

                if not mapped:
                    try:
                        message_type = struct.unpack('! B', tcp.data[:1])[0]
                        if message_type <= 6:
                            print('Probably Client message!')
                            print('Type: {} Length: {}'.format(message_type, len(tcp.data)))
                        if message_type == 0 and len(tcp.data) == 20:
                            print('Probably SetPixelFormat message!')
                            mapped = True
                        elif message_type == 2 and len(tcp.data) == 4:
                            print('Probably SetEncodings message!')
                            mapped = True
                        elif message_type == 3 and len(tcp.data) == 10:
                            try:
                                struct.unpack('! B H H H H', tcp.data[1:])
                            except:
                                raise Exception('Can\'t decode message as FramebufferUpdateRequest message!')
                            else:
                                print('FramebufferUpdateRequest message:')
                                incr, x_pos, y_pos, width, height = struct.unpack('! B H H H H', tcp.data[1:])
                                print('Incremental: {}\nX Pos: {}\nY Pos: {}\nWidth: {}\nHeight: {}'\
                                      .format(bool(incr), int(x_pos), int(y_pos), int(width), int(height)))
                                mapped = True
                        elif message_type == 4 and len(tcp.data) == 8:
                            try:
                                struct.unpack('! B 2x I', tcp.data[1:])
                            except:
                                raise Exception('Can\'t decode message as KeyEvent message!')
                            else:
                                print('KeyEvent message:')
                                down_flag, key = struct.unpack('! B 2x I', tcp.data[1:])
                                print('Down flag: {}\nKey hex code: {}'\
                                      .format(bool(down_flag), hex(key)))
                                mapped = True
                        elif message_type == 5 and len(tcp.data) == 6:
                            try:
                                struct.unpack('! B H H', tcp.data[1:])
                            except:
                                raise Exception('Can\'t decode message as PointerEvent message!')
                            else:
                                print('PointerEvent message:')
                                button, x_pos, y_pos = struct.unpack('! B H H', tcp.data[1:])
                                if button != 0:
                                    print('Mouse button pressed: {}'.format(button))
                                print('X Pos: {} Y Pos: {}'.format(x_pos, y_pos))
                                mapped = True
                        elif message_type == 6:
                            print('Probably ClientCutText message!')
                            mapped = True
                    except Exception as e:
                        print('Unexpected error: {}'.format(e))

                    print()


                print()

main()
