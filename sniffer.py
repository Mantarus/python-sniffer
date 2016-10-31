import itertools
import socket
import struct
import sys

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
        # print('Receive packet #{} at {}'.format(str(cnt), str(addr[0])))
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

                # if tcp.dest_port in VNC.ports or tcp.src_port in VNC.ports:
                #     print('Probably VNC Packet!')
                #     print('SRC IP: {} SRC Port: {} DST IP: {} DST PORT: {}'
                #           .format(ipv4.src, tcp.src_port, ipv4.target, tcp.dest_port))

                print('SRC IP: {} SRC Port: {} DST IP: {} DST Port: {}'
                      .format(ipv4.src, tcp.src_port, ipv4.target, tcp.dest_port))
                print('Data length: {}'.format(len(tcp.data)))

                mapped = False

                if not mapped:
                    try:
                        tcp.data.decode('utf-8')
                    except:
                        pass
                    else:
                        if len(tcp.data) == 12 and tcp.data.decode('utf-8')[:3] == 'RFB':
                            vnc = VNCProtocolVersion(tcp.data)
                            print('Protocol version message:')
                            print('Version: {}'.format(vnc.version))
                        mapped = True

                if not mapped:
                    try:
                        vnc = VNCClientMessage(tcp.data)
                        if vnc.message_code == 0 and len(tcp.data) >= 16:
                            # FramebufferUpdate
                            try:
                                vnc_cm = VNCFrameBufferUpdateMessage(tcp.data)
                            except:
                                raise Exception('Can\'t decode message as FramebufferUpdate message!')
                            else:
                                print(vnc_cm)
                                mapped = True
                        if vnc.message_code == 0 and len(tcp.data) == 20:
                            # SetPixelFormat
                            print('Probably SetPixelFormat message!')
                            mapped = True
                        elif vnc.message_code == 2 and len(tcp.data) == 4:
                            # SetEncodings
                            print('Probably SetEncodings message!')
                            mapped = True
                        elif vnc.message_code == 3 and len(tcp.data) == 10:
                            # FramebufferUpdateRequest
                            try:
                                vnc_cm = VNCFrameBufferUpdateRequestMessage(tcp.data)
                            except:
                                raise Exception('Can\'t decode message as FramebufferUpdateRequest message!')
                            else:
                                print(vnc_cm)
                                mapped = True
                        elif vnc.message_code == 4 and len(tcp.data) == 8:
                            # KeyEvent
                            try:
                                vnc_cm = VNCKeyEventMessage(tcp.data)
                            except:
                                raise Exception('Can\'t decode message as KeyEvent message!')
                            else:
                                print(vnc_cm)
                                mapped = True
                        elif vnc.message_code == 5 and (len(tcp.data) == 6 or len(tcp.data) == 12):
                            # PointerEvent
                            try:
                                vnc_cm = VNCPointerEventMessage(tcp.data)
                            except:
                                raise Exception('Can\'t decode message as PointerEvent message!')
                            else:
                                print(vnc_cm)
                                mapped = True
                        elif vnc.message_code == 6:
                            # ClientCutText
                            print('Probably ClientCutText message!')
                            mapped = True
                    except Exception as e:
                        print('Unexpected error: {}'.format(e))

                    print()


                print()

if __name__ == '__main__':
    main()
